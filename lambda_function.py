import json
import boto3
import urllib3
import urllib.request
import os
import botocore.session
import base64
import logging
from hashlib import sha256
import hmac
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

#
# CONFIGURATION ENVIRONMENT Variables in AWS Lambda
#
# General configuration
githubOrg = os.environ['githubOrg']
githubOrgKey = os.environ['githubOrgKey']
webHookSecret = os.environ['githubOrgSecret']

# Repository Protection configuration
str_protection_lock_branch = os.environ['protection_lock_branch']
str_protection_enforce_admins = os.environ['protection_enforce_admins']

# Environment Variables are strings, GitHub API needs boolean values. Will convert
if str_protection_lock_branch == "True":
    protection_lock_branch = True

if str_protection_enforce_admins == "True":
    protection_enforce_admins = True

# Create JSON for protection APIs
protJSON = {
    "lock_branch": protection_lock_branch,
    "enforce_admins": protection_enforce_admins,
    "required_status_checks": None,
    "restrictions": None,
    "required_pull_request_reviews": None
}

# Create header for API calls
headers = {
    'Authorization': 'Bearer ' + githubOrgKey, 
    'Content-Type': 'application/json', 
    'Accept': 'application/vnd.github+json', 
    'X-GitHub-Api-Version': '2022-11-28'
}

# GitHub API: Protection Subroutine (GET)
def get_protection_status(repo_name):
    prot_url = "https://api.github.com/repos/" + githubOrg + "/" + repo_name + "/branches/main/protection"
    http = urllib3.PoolManager()
    response = http.request('GET',
                        prot_url,
                        headers = headers,
                        retries = False)
    return (json.loads(response.data))

# GitHub API: Protection Subroutine (PUT)
def prot_lock_branch(repo_name, protJSON):
    prot_url = "https://api.github.com/repos/" + githubOrg + "/" + repo_name + "/branches/main/protection"
    http = urllib3.PoolManager()
    encoded_prot_body = json.dumps(protJSON);
    http.request("PUT",
                prot_url,
                headers=headers,
                body=bytes(encoded_prot_body, 'utf-8'))

# GitHub API: Issue Creation Subroutine (POST)
def createIssue(repoName, issue):
    url = "https://api.github.com/repos/" + githubOrg + "/" + repoName + "/issues"
    http = urllib3.PoolManager()
    encoded_body = json.dumps(issue);
    response = http.request('POST',
                            url,
                            headers = headers,
                            body=encoded_body,
                            retries = False)


# Signature validation for GitHub WebHook
def equal_hash(event, secret_value):
  sigExpected = str(event["headers"]["x-hub-signature-256"].replace("sha256=", ""))
  sigCalculated = str(hmac.new(secret_value.encode("UTF-8"), event["body"].encode("UTF-8"), sha256).hexdigest())
  return hmac.compare_digest(sigCalculated, sigExpected)

# Main function
def lambda_handler(event, context):
    # Hook Signature verifier
    if "headers" in event:
        # Secret for subsequent invocation
        if "x-hub-signature-256" not in event["headers"]:
            authFail = {"AuthFailed" : "Header missing"}
            return {
                'statusCode': 503,
                'body': json.dumps(event["headers"])
            }
        else:
            signature_code = equal_hash(event, webHookSecret)
    
    #if not signature_code:
    #    return {
    #        "statusCode": 401
    #    }
    #    exit(0)
    
    # Read data from header and payload
    header_event = event["headers"]["x-github-event"]
    body = json.loads(event["body"])
    repo_name = body["repository"]["name"]
    repo_desc = body["repository"]["description"]
    repo_id = body["repository"]["id"]
    repo_created_at = body["repository"]["created_at"]
    created_by = body["sender"]["login"]
    
    # Listening on initial Push only
    if header_event == "push":
        issue = {
            "title": "Initial Code was PUSHED into the Repository",
            "body":"@antnhrbr - Code has been pushed the Repository: " + repo_name + " by " + created_by + ". Main branch is created and will be protected now by:<br /><br />- Lock Branch: " + str_protection_lock_branch + "<br />- Enforce Admins: " + str_protection_enforce_admins + "<br /><br />Good luck!"
        }

        # Create the issue if it's an initial push (main branch has been protected)
        protection_status = get_protection_status(repo_name)
        if "message" in protection_status:
            if protection_status["message"] == "Branch not protected":
                createIssue(repo_name, issue)
                # protect the main branch
                prot_lock_branch(repo_name, protJSON)
                status = {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": json.dumps({"status": "Branch has been protected and issue was created"})
            }
        else:
            status = {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": json.dumps({"status": "Branch is protected. Won't protect or create issue"})
            }
    else:
        status = {
            "statusCode": 401,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps({"status": "Unauthorized"})
        }
    
    return status
