import os
import requests
from datetime import datetime, timezone
from supabase import create_client, Client
import json
import ssl
import socket
from urllib.parse import urlparse
import dns.resolver
import ipaddress
import credentials

# Initialize Supabase client
supabase_url = credentials.supabase_url
supabase_key = credentials.supabase_key

if not supabase_url or not supabase_key:
    raise ValueError("SUPABASE_URL and SUPABASE_KEY environment variables must be set.")

supabase: Client = create_client(supabase_url, supabase_key)

def fetch_hosts():
    """
    Fetch active hosts from the 'hosts' table in Supabase.
    """
    response = (
        supabase.table("hosts")
        .select("*, checks(short_name)")
        .eq("active", True)
        .execute()
    )
    print("Supabase returned " + str(len(response.data)) + " item(s)")

    # Safely check for data and errors
    if response.data and len(response.data) > 0:
        return response.data  # Return the data if present
    elif "error" in response and response.error:
        raise Exception(f"Error fetching hosts: {response.error['message']}")
    else:
        raise Exception("Unexpected response from Supabase: No data or error found.")


def save_result(host_id, check_id, test_result, test_reason):
    """
    Save the test result to the 'results' table in Supabase.
    """
    data = {
        "host_id": host_id,
        "result": test_result,
        "reason": test_reason,
        "check_id": check_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    response = supabase.table("results").insert(data).execute()

    # Safely check for data and errors
    if response.data and len(response.data) > 0:
        return response.data  # Return the data if present
    else:
        raise Exception("Unexpected response from Supabase for INSERT to result table.")


def perform_check(check_id, host):
    """
    Perform the appropriate check based on the check_id.
    """
    check_functions = {
        "up_or_down": check_up_or_down,
        "http_code": check_http_code,
        "page_content": check_page_content,
        "tls_version": check_tls_version,
        "certificate_expiry": check_certificate_expiry,
        "dns_response": check_dns_response,
        "dns_basic": check_dns_basic,
    }

    check_function = check_functions.get(check_short_name)
    if not check_function:
        return {"test_result": "failure", "test_reason": f"Unsupported check: {check_short_name}"}

    return check_function(host)


# Use the ip_address function from the ipaddress module to check if the input is a valid IP address
def check_ip(ip):
	try:
		ipaddress.ip_address(ip)
		return True
	except ValueError:
		# If the input is not a valid IP address, catch the exception and print an error message
		return False


# Individual Check Functions

def check_up_or_down(host):
    url = host["url"]
    expected_result = host.get("expected_result", "True")

    # Validate URL
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    if parsed_url.scheme != "https":
        return {"status": "failure", "reason": "URL is not using HTTPS"}

    # DNS check required unless it's an IP address
    if check_ip(hostname) == False:
        try:
            dns_check(hostname)
        except:
            return {"test_result": "failure", "test_reason": f"Host name is notanIP address and not resolved by DNS."}

    # Basic socket connection test
    try:
        socket.create_connection((hostname, 443), timeout=5)
        if expected_result.casefold() == "false":
            return {"test_result": "failure", "test_reason": f"Connection to {hostname} accepted but this was not expected."}
        else:
            return {"test_result": "success", "test_reason": f"Connection to {hostname} accepted as expected"}
    except (socket.timeout, ConnectionRefusedError):
        print(f"Expected result: {str(expected_result)}")
        if expected_result.casefold() == "true":
            return {"test_result": "failure", "test_reason": f"Connection to {hostname} failed"}
        else:
            return {"test_result": "success", "test_reason": f"Connection to {hostname} refused as expected"}
    
    #################
    # try:
    #     response = requests.get(url, timeout=5)
    #     response.raise_for_status()
    #     return {"test_result": "success", "test_reason": None}
    # except Exception as e:
    #     return {"test_result": "failure", "test_reason": str(e)}


def check_http_code(host):
    url = host["url"]
    print(f"{url}")
    expected_http_code = json.loads(host.get("expected_result", "200"))

    try:
        response = requests.get(url, timeout=5)
        if response.status_code == expected_http_code:
            return {"test_result": "success", "test_reason": f"HTTP response {expected_http_code} as expected"}
        else:
            return {
                "test_result": "failure",
                "test_reason": f"Expected status HTTP {expected_http_code}, got {response.status_code}",
            }
    except Exception as e:
        return {"test_result": "failure", "test_reason": str(e)}


# INTERNAL SCRIPT check for DNS
def dns_check(hostname, resolver_ip="192.168.1.2"):

    dns_type = "A"

    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ resolver_ip ]
        result = resolver.resolve(hostname, dns_type)

        # Debug stuff
        print(f"DEBUG: {len(result)}")
        for val in result:
            print(f"DEBUG: {val.to_text()}")

        # If more than zero responses then compare for expected_response of true|false
        if len(result) > 0:
            return True
    except Exception as e:
        print(f"INFO: {str(e)}")

    return False


# Confirm that a DNS record exists at all
def check_dns_basic(host):
    parsed_url = urlparse(host["url"])
    hostname = parsed_url.hostname
    expected_dict = json.loads(host.get("expected_result"))

    resolver_ip = expected_dict.get("resolver_ip", "8.8.8.8")
    dns_type = expected_dict.get("type", "A")
    expected_response = expected_dict.get("expected_response", "true")

    print(f"INFO: Check for {expected_response} {dns_type} records exists from resolver {resolver_ip} for name {hostname}")

    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ resolver_ip ]
        result = resolver.resolve(hostname, dns_type)

        # Debug stuff
        print(len(result))
        for val in result:
            print(f"{val.to_text()}")

        # If more than zero responses then compare for expected_response of true|false
        if len(result) > 0 and expected_response.casefold() == "true":
            print(f"INFO: Success got a record from resolver {resolver_ip} for name {hostname}")
            return {"test_result": "success", "test_reason": f"Got {expected_response} for name {hostname} from resolver {resolver_ip}"}
        
        return {
            "test_result": "failure",
            "test_reason": f"The DNS query name does not exist: {hostname}.",
        }
    except Exception as e:
        print(f"INFO: {str(e)}")
        if expected_response.casefold() == "false":
            print(f"INFO: Success no record from resolver {resolver_ip} for name {hostname}")
            return {"test_result": "success", "test_reason": f"The DNS query name does not exist: {hostname}."}

        return {"test_result": "failure", "test_reason": str(e)}


# Confirm that a DNS response equals what was expected
def check_dns_response(host):
    parsed_url = urlparse(host["url"])
    hostname = parsed_url.hostname
    expected_dict = json.loads(host.get("expected_result"))

    print(f"INFO: Check {expected_dict['expected_response']} from resolver {expected_dict['resolver_ip']} for name {hostname}")

    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ expected_dict['resolver_ip'] ]
        result = resolver.resolve(hostname, expected_dict['type'])
        # Loop the returned info to check against expected IP
        for val in result:
            if val.to_text() == expected_dict['expected_response']:
                print(f"INFO: Success got {expected_dict['expected_response']} from resolver {expected_dict['resolver_ip']} for name {hostname}")
                return {"test_result": "success", "test_reason": f"Got {expected_dict['expected_response']} for name {hostname} from resolver {expected_dict['resolver_ip']}"}
        
        return {
            "test_result": "failure",
            "test_reason": f"Expected IP {expected_dict['expected_response']} not returned by resolver {expected_dict['resolver_ip']} for type {expected_dict['type']}",
        }
    except Exception as e:
        return {"test_result": "failure", "test_reason": str(e)}


def check_page_content(host):
    url = host["url"]
    expected_result = host.get("expected_result")
    try:
        response = requests.get(url, timeout=5)
        if expected_result in response.text:
            return {"test_result": "success", "test_reason": None}
        else:
            return {
                "test_result": "failure",
                "test_reason": f"Text '{expected_result}' not found on page",
            }
    except Exception as e:
        return {"test_result": "failure", "test_reason": str(e)}


def check_tls_version(host):
    url = host["url"]
    try:
        hostname = url.replace("https://", "").split("/")[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                if ssock.version() not in ["TLSv1.2", "TLSv1.3"]:
                    return {"test_result": "failure", "test_reason": f"Unsupported TLS version: {ssock.version()}"}
                return {"test_result": "success", "test_reason": None}
    except Exception as e:
        return {"test_result": "failure", "test_reason": str(e)}


def check_certificate_expiry(host):
    url = host["url"]
    expected_result = host.get("expected_result")

    try:
        hostname = url.replace("https://", "").split("/")[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                if not_after < datetime.now() and expected_result.casefold() == "true":
                    return {"test_result": "failure", "test_reason": "UNEXPECTED: Certificate is expired"}
                return {"test_result": "success", "test_reason": "Certificate is not expired"}
    except Exception as e:
        response = str(e)
        if response.find("certificate has expired") and expected_result.casefold() == "true":
            return {"test_result": "failure", "test_reason": "Certificate is expired"}
        elif response.find("certificate has expired") and expected_result.casefold() == "false":
            return {"test_result": "failure", "test_reason": "Certificate is expired"}
        return {"test_result": "failure", "test_reason": f"Unknown error, {str(e)}"}
    

if __name__ == "__main__":
    #def lambda_handler(event, context):
    """
    Lambda function to fetch hosts, perform checks, and save results to Supabase.
    """
    # Fetch hosts from Supabase
    hosts = fetch_hosts()
    for host in hosts:
        if not host.get("active", False):
            continue

        url = host["url"]
        check_short_name = host.get("checks", {}).get("short_name")
        host_id = host["id"]
        check_id = host["check_id"]

        print(f"Running check for URL: {url}, check name: {check_short_name}")

        # Perform the appropriate check
        check_result = perform_check(check_short_name, host)

        # Save the result to Supabase
        save_result(host_id, check_id, check_result["test_result"], check_result["test_reason"])


    print(json.dumps(
        {
            "statusCode": 200,
            "body": "Checks completed successfully."
        },
        indent=4
        )
    )
