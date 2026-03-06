import os
import json
import boto3
from decimal import Decimal
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

# ---------------------------------------------------
# CORS
# ---------------------------------------------------
def get_cors_headers():
    origin = "https://www.admin.jobsyme.com"
    return {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
        "Access-Control-Allow-Methods": "POST,OPTIONS",
        "Access-Control-Allow-Credentials": "true"
    }


# ---------------------------------------------------
# Assume Cross Account Role
# ---------------------------------------------------
def get_cross_account_table():
    # Get Role ARN from environment variable.
    # This is the IAM role in another AWS account that we want to assume
    # in order to access its DynamoDB table.
    role_arn = os.environ["CANDIDATE_DYNAMO_ROLE_ARN"]
    table_name = os.environ["CANDIDATES_TABLE"]

    # Create an STS (Security Token Service) client.
    # STS is used to assume roles and get temporary credentials.
    sts = boto3.client("sts")

    # Assume the IAM role in the target account.
    # This returns temporary security credentials that allow us
    # to access resources in that other AWS account.
    response = sts.assume_role(
        RoleArn=role_arn,  # IAM Role to assume (target account role)
        RoleSessionName="AdminCreateAssistantSession"    # A name for this temporary session
    )

    # Extract temporary credentials returned by STS
    credentials = response["Credentials"]
    # Create a DynamoDB resource using the temporary credentials.
    # These credentials now have the permissions of the assumed role.
    dynamodb = boto3.resource(
        "dynamodb",
        aws_access_key_id=credentials["AccessKeyId"],  # Temporary Access Key
        aws_secret_access_key=credentials["SecretAccessKey"],   # Temporary Secret Key
        aws_session_token=credentials["SessionToken"], # Temporary Session Token
    )
    
    # Return the DynamoDB table object from the target account.
    # Now we can perform operations like put_item, get_item, query, scan, etc.
    return dynamodb.Table(table_name)



# ---------------------------------------------------
# Lambda Handler
# ---------------------------------------------------
def handler(event, context):
    cors = get_cors_headers()

    # Preflight
    if event.get("httpMethod") == "OPTIONS":
        return {
            "statusCode": 200,
            "headers": cors,
            "body": json.dumps({"message": "Preflight OK"})
        }

    try:
        # -----------------------------------------
        # Admin Authentication (Authorizer)
        # -----------------------------------------
        admin_id = event.get("requestContext", {}).get("authorizer", {}).get("principalId")

        if not admin_id:
            return {
                "statusCode": 401,
                "headers": cors,
                "body": json.dumps({"message": "Unauthorized"})
            }

        
        # -----------------------------------------
        # Fetch All Candidates
        # -----------------------------------------
        candidate_table = get_cross_account_table()
        candidates = []

        scan_response = candidate_table.scan()
        candidates.extend(scan_response.get("Items", []))

        # Pagination handling
        while "LastEvaluatedKey" in scan_response:
            scan_response = candidate_table.scan(
                ExclusiveStartKey=scan_response["LastEvaluatedKey"]
            )
            candidates.extend(scan_response.get("Items", []))

        if not candidates and len(candidates) == 0:
            return {
                "statusCode": 404,
                "headers": cors,
                "body": json.dumps({"message": "No candidates found"})
            }
        
        final_response = get_all_candidates(candidates)
        return {
            "statusCode": 200,
            "headers": cors,
            "body": json.dumps({
                "message": "Fetch Candidates successfully",
                "candidates": json.dumps(convert(final_response))
            })
        }

    except ClientError as e:
        return {
            "statusCode": 500,
            "headers": cors,
            "body": json.dumps({
                "message": "AWS error",
                "error": str(e)
            })
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "headers": cors,
            "body": json.dumps({
                "message": "Internal server error",
                "error": str(e)
            })
        }

def get_all_candidates(candidates):
    response = []
    for item in candidates:
        candidate = {
            "candidate_id": item.get("candidate_id"),
            "jaa_candidate_id": item.get("jaa_candidate_id"),
            "user_id": item.get("user_id"),
            "first_name": item.get("first_name"),
            "last_name": item.get("last_name"),
            "email": item.get("email"),
            "phone": item.get("phone"),
            "github": item.get("github"),
            "linkedin": item.get("linkedin"),
            "resumeUrl": item.get("resumeUrl"),
            "resumeFileExtension": item.get("resumeFileExtension"),
            "assistantAssignedTo": item.get("assistantAssignedTo"),
            "address": {
                "street": item.get("address", {}).get("street"),
                "city": item.get("address", {}).get("city"),
                "state": item.get("address", {}).get("state"),
                "country": item.get("address", {}).get("country"),
                "zip": item.get("address", {}).get("zip")
            },
            "careerDetails": {
                "highestEducation": item.get("careerDetails", {}).get("highestEducation"),
                "yearsExperience": item.get("careerDetails", {}).get("yearsExperience"),
                "skills": item.get("careerDetails", {}).get("skills"),
                "preferredJobType": item.get("careerDetails", {}).get("preferredJobType"),
                "dateAvailable": item.get("careerDetails", {}).get("dateAvailable"),
                "workAuthorized": item.get("careerDetails", {}).get("workAuthorized"),
                "visaRequired": item.get("careerDetails", {}).get("visaRequired"),
                "validDriverLicense": item.get("careerDetails", {}).get("validDriverLicense"),
                "willingToRelocate": item.get("careerDetails", {}).get("willingToRelocate"),
                "vaccinationStatus": item.get("careerDetails", {}).get("vaccinationStatus")
            },
            "jobPreferences": {
                "preferredJobTitles": item.get("jobPreferences", {}).get("preferredJobTitles"),
                "preferredJobType": item.get("jobPreferences", {}).get("preferredJobType"),
                "blockedCompanies": item.get("jobPreferences", {}).get("blockedCompanies"),
                "salaryExpectation": item.get("jobPreferences", {}).get("salaryExpectation"),
                "timeZone": item.get("jobPreferences", {}).get("timeZone")
            },
            "demographic": {
                "gender": item.get("demographic", {}).get("gender"),
                "pronouns": item.get("demographic", {}).get("pronouns"),
                "ethnicIdentity": item.get("demographic", {}).get("ethnicIdentity"),
                "sexualOrientation": item.get("demographic", {}).get("sexualOrientation"),
                "veteranStatus": item.get("demographic", {}).get("veteranStatus"),
                "disabilityStatus": item.get("demographic", {}).get("disabilityStatus")
            },
            "dedicatedGmailAccount": {
                "email": item.get("dedicatedGmailAccount", {}).get("email"),
                "password": item.get("dedicatedGmailAccount", {}).get("password")
            },
            "createdAt": item.get("createdAt"),
            "updatedAt": item.get("updatedAt")
        }
        response.append(candidate)
    return response




def convert(obj):
        if isinstance(obj, list):
            return [convert(i) for i in obj]
        elif isinstance(obj, dict):
            return {k: convert(v) for k, v in obj.items()}
        elif isinstance(obj, Decimal):
            return int(obj) if obj % 1 == 0 else float(obj)
        return obj