import os
import json
import socket
import requests
import ssl
from datetime import datetime
from urllib.parse import urlparse
import boto3


def check_page(url, expected_text, expected_http_status):
    """
    Checks if a page meets the following conditions:
    - Returns the expected HTTP status.
    - Contains the expected text.
    - Uses TLS 1.2 or later.
    - Has a valid HTTPS certificate.
    """
    try:
        # Validate URL
        parsed_url = urlparse(url)
        if parsed_url.scheme != "https":
            return {"status": "failure", "reason": "URL is not using HTTPS"}

        # Make the GET request
        response = requests.get(url, timeout=10)
        if response.status_code != expected_http_status:
            return {
                "status": "failure",
                "reason": f"HTTP status code {response.status_code} does not match expected {expected_http_status}",
            }

        # Check for the expected text
        if expected_text and expected_text not in response.text:
            return {"status": "failure", "reason": f"Text '{expected_text}' not found on page"}

        # Check TLS version and certificate expiration
        ssl_context = ssl.create_default_context()
        with socket.create_connection((parsed_url.hostname, 443)) as sock:
            with ssl_context.wrap_socket(sock, server_hostname=parsed_url.hostname) as ssock:
                cert = ssock.getpeercert()

                # Check TLS version
                if ssock.version() not in ("TLSv1.2", "TLSv1.3"):
                    return {"status": "failure", "reason": "TLS version is not 1.2 or later"}

                # Check certificate expiration
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                if not_after < datetime.utcnow():
                    return {"status": "failure", "reason": "Certificate has expired"}

        return {"status": "success", "reason": "All checks passed"}

    except Exception as e:
        return {"status": "failure", "reason": str(e)}


def send_sns_notification(sns_topic, message, subject="Canary Test Failure"):
    """
    Sends a notification using AWS SNS.
    """
    sns_client = boto3.client("sns")
    response = sns_client.publish(
        TopicArn=sns_topic,
        Subject=subject,
        Message=message
    )
    return response


def get_inputs_from_dynamodb(table_name):
    """
    Fetches monitoring inputs from a DynamoDB table.
    """
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(table_name)
    response = table.scan()
    return response.get("Items", [])


def update_dynamodb_record(table_name, record_id, result, reason, sns_notified):
    """
    Updates a record in DynamoDB with the test result, timestamp, and SNS notification flag.
    """
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(table_name)
    table.update_item(
        Key={"id": record_id},
        UpdateExpression="SET test_result = :result, test_reason = :reason, last_tested = :timestamp, sns_notified = :sns_notified",
        ExpressionAttributeValues={
            ":result": result,
            ":reason": reason,
            ":timestamp": datetime.utcnow().isoformat(),
            ":sns_notified": sns_notified
        }
    )


def run_canary(table_name):
    """
    Executes the synthetic monitoring test for each record in DynamoDB.
    """
    inputs = get_inputs_from_dynamodb(table_name)
    client = boto3.client("cloudwatch")
    namespace = "SyntheticMonitoring/CanaryChecks"

    for record in inputs:
        url = record.get("url")
        expected_text = record.get("expected_text")
        expected_http_status = record.get("expected_http_status", 200)
        sns_topic = record.get("sns")  # Optional
        record_id = record.get("id")
        sns_notified = record.get("sns_notified", False)  # Check if notification was sent previously

        print(f"Running check for URL: {url}, expected text: '{expected_text}'")

        # Perform the page check
        result = check_page(url, expected_text, expected_http_status)

        # Determine if SNS should be sent (only send if failed and sns_notified is False)
        if result["status"] == "failure" and sns_topic and not sns_notified:
            subject = f"Canary Test Failure for {url}"
            message = f"URL: {url}\nResult: {result['status']}\nReason: {result['reason']}"
            send_sns_notification(sns_topic, message, subject)

            # Update DynamoDB to indicate that SNS was sent
            sns_notified = True

        # If the test passes, clear the sns_notified flag
        if result["status"] == "success" and sns_notified:
            sns_notified = False

        # Update DynamoDB with the result
        update_dynamodb_record(
            table_name,
            record_id,
            result["status"],
            result["reason"],
            sns_notified
        )

        # Publish metrics to CloudWatch
        client.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": "PageAvailability",
                    "Dimensions": [{"Name": "URL", "Value": url}],
                    "Value": 1 if result["status"] == "success" else 0,
                    "Unit": "Count",
                }
            ],
        )

        print(f"Result for {url}: {result}")

# Lambda handler
def lambda_handler(event, context):
    """
    AWS Lambda entry point.
    """
    # Get the DynamoDB table name from the event or environment variable
    table_name = os.environ.get('DYNAMODB_TABLE_NAME')
    if not table_name:
        raise ValueError("DYNAMODB_TABLE_NAME environment variable is not set")

    try:
        run_canary(table_name)
        return {
            "statusCode": 200,
            "body": json.dumps({"message": "Canary checks completed successfully"})
        }
    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }