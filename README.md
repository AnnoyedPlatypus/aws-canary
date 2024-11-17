## Squawker

### Description

Lambda function in Python that takes inputs from a DynamoDB table and runs various tests against the URLs to confirm they're operating as expected.

Tests currently implemented,

- Page is reachable
- HTTP response. e.g. 200, 302, 404
- Contents such as a word. e.g. "example"
- Certificate not expired
- Web server is running TLS 1.2 or later

On failure an AWS SNS topic will be used to send a notification of the failure. The topic needs an email subscriber to function. Only one notification is sent at failure time and on-going failures will not notify again.

The function is triggered every 60min by an Eventbridge function.

Cloudwatch logging captures the output of the Lambda function and retains the data for one week.

### Example DynamoDB Record

```
{
  "id": {
    "S": "6"
  },
  "description": {
    "S": "Test to check for an HTTP 302 repsonse from a server or web page."
  },
  "expected_http_status": {
    "N": "302"
  },
  "expected_text": {
    "S": ""
  },
  "last_tested": {
    "S": "2024-11-17T06:10:32.223968"
  },
  "sns": {
    "S": "arn:aws:sns:<region>>:<account>:emailCanaryNotification"
  },
  "sns_notified": {
    "BOOL": true
  },
  "test_reason": {
    "S": "HTTP status code 200 does not match expected 302"
  },
  "test_result": {
    "S": "failure"
  },
  "url": {
    "S": "https://www.example.com"
  }
}
```

### Requirements

To get the Python `requests` library included (as AWS Lambda does not include it by default), we need to create a Lambda Layer that includes it.

Create a sub folder `lambda_layers/python` and install `requests` in that folder `pip install requests -t ./`. Zip up the libraries (`cd ..` and `zip -r python_modules.zip .` noting that trailing ".") that are in the `python` folder and use that zip to create a Python layer in Lambda. Include this in your Lambda function.
