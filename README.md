# AWSLambdaPythonWebHook
Python Code for GitHub Webhook listener.

## Installation
1. Create least privilege fine grained Bearer Token in your GitHub Org with permissions:
- Read and Write access to administration (to lock the main branch)
- Read and Write access to issues (to create the issue)
2. Create [AWS Lambda](https://eu-central-1.console.aws.amazon.com/lambda/home?region=eu-central-1#/functions) with Python 3.8 Environment
3. Add funcional URL to Lambda
4. Configure this URL in your organizational Hook (POST on push only) 
5. Add Environment Variables to AWS Lambda:
- `githubOrg` set to your Orgname
- `githubOrgKey` set to your created Token
- `githubOrgSecret` set to your Secret
- `protection_enforce_admins` set to `True` or `False`
- `protection_lock_branch` set to `True` or `False`  
6. Enable Webhook in GitHub

## Supported protection
Currently `protection_enforce_admins` and `protection_lock_branch` are supported to protect the main branch as part of the PoC. No further fine grained controls have been implemented as of now.

## Enhancements of the solution
The solution can be further modified with additional environment variables in the Lambda configuraton to set more fine grained permissions on the branch, as per [documentation](https://docs.github.com/en/rest/branches/branch-protection?apiVersion=2022-11-28#update-branch-protection), like:

  - `required_status_checks`
  - `required_pull_request_reviews`
  - `restrictions` to teams and users
  - ...

Adding the variables will also require to change the `protJSON` JSON sent to the protection endpoint accordingly, making it to some extent a diligence, but a one time only work unless the GitHub API changes and provides additional parameters.
