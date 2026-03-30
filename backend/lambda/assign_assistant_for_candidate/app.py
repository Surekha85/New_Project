
import os
import json
import boto3
import jwt
from datetime import datetime,timezone,timedelta
from botocore.exceptions import ClientError

# AWS clients
secrets_client=boto3.client("secretsmanager")
sts_client=boto3.client("sts")

# caches
JWT_SECRET_CACHE=None
ROLE_CACHE={}
ROLE_EXPIRY={}

# CORS headers
def get_cors_headers():
    origin = 'http://localhost:3000'
    return{
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Headers":"Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
        "Access-Control-Allow-Methods":"POST,OPTIONS",
        "Access-Control-Allow-Credentials":"true"
    }

# get JWT secret (cached)
def get_jwt_secret():
    global JWT_SECRET_CACHE
    if JWT_SECRET_CACHE:
        return JWT_SECRET_CACHE
    response=secrets_client.get_secret_value(SecretId=os.environ["JWT_SECRET_NAME"])
    secret=json.loads(response["SecretString"])
    JWT_SECRET_CACHE=secret["jwt_secret"]
    return JWT_SECRET_CACHE

# verify admin token
def verify_admin_token(event):
    headers=event.get("headers",{})
    auth=headers.get("Authorization") or headers.get("authorization")
    if not auth:
        return None,"Missing Authorization"
    if not auth.startswith("Bearer "):
        return None,"Invalid token format"
    token=auth.split(" ")[1]
    try:
        decoded=jwt.decode(token,get_jwt_secret(),algorithms=["HS256"])
        if decoded.get("user_type")!="admin":
            return None,"Unauthorized"
        return decoded,None
    except jwt.ExpiredSignatureError:
        return None,"Token expired"
    except jwt.InvalidTokenError:
        return None,"Invalid token"

# assume cross account role with cache
def assume_role(role_arn):
    now=datetime.now(timezone.utc)
    creds=None
    if role_arn in ROLE_CACHE:
        if now < (ROLE_EXPIRY[role_arn]-timedelta(minutes=2)):
            creds=ROLE_CACHE[role_arn]
    if not creds:
        response=sts_client.assume_role(RoleArn=role_arn,RoleSessionName="AdminAssignAssistant")
        creds=response["Credentials"]
        ROLE_CACHE[role_arn]=creds
        ROLE_EXPIRY[role_arn]=creds["Expiration"]
    return boto3.client(
        "dynamodb",
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )

# assign candidate to assistant
def assign_candidate(assistant_id, candidate_id):

    candidate_dynamo = assume_role(os.environ["CANDIDATE_DYNAMO_ROLE_ARN"])
    assistant_dynamo = assume_role(os.environ["ASSISTANT_DYNAMO_ROLE_ARN"])

    candidate_table = os.environ["CANDIDATES_TABLE"]
    assistant_table = os.environ["ASSISTANTS_TABLE"]

    # ===============================
    # STEP 1: GET CANDIDATE
    # ===============================
    candidate = candidate_dynamo.get_item(
        TableName=candidate_table,
        Key={"jaa_candidate_id": {"S": candidate_id}}
    )

    if "Item" not in candidate:
        return {"message": "Candidate not found"}

    candidate_item = candidate["Item"]

    # existing assistants list
    existing_list = candidate_item.get("assignedAssistants", {}).get("L", [])

    # ===============================
    # STEP 2: GET NEW ASSISTANT
    # ===============================
    new_assistant = assistant_dynamo.get_item(
        TableName=assistant_table,
        Key={"assistantId": {"S": assistant_id}}
    )

    if "Item" not in new_assistant:
        return {"message": "Assistant not found"}

    new_item = new_assistant["Item"]

    first_name = new_item.get("first_name", {}).get("S", "")
    last_name = new_item.get("last_name", {}).get("S", "")
    assistant_name = f"{first_name} {last_name}".strip()

    now = datetime.utcnow().isoformat()

    try:

        # ===============================
        # STEP 3: CHECK DUPLICATE
        # ===============================
        for a in existing_list:
            if a.get("M", {}).get("assistantId", {}).get("S") == assistant_id:
                return {"message": "Assistant already assigned to this candidate"}

        # ===============================
        # STEP 4: ADD TO CANDIDATE TABLE
        # ===============================
        new_assistant_entry = {
            "M": {
                "assistantId": {"S": assistant_id},
                "assistantName": {"S": assistant_name}
            }
        }

        candidate_dynamo.update_item(
            TableName=candidate_table,
            Key={"jaa_candidate_id": {"S": candidate_id}},
            UpdateExpression="""
                SET assignedAssistants = list_append(
                    if_not_exists(assignedAssistants, :empty),
                    :newAssistant
                ),
                updatedAt = :time
            """,
            ExpressionAttributeValues={
                ":newAssistant": {"L": [new_assistant_entry]},
                ":empty": {"L": []},
                ":time": {"S": now}
            }
        )

        # ===============================
        # STEP 5: ADD TO ASSISTANT TABLE
        # ===============================
        assistant_dynamo.update_item(
            TableName=assistant_table,
            Key={"assistantId": {"S": assistant_id}},
            UpdateExpression="""
                SET assigned_candidates =
                list_append(if_not_exists(assigned_candidates, :empty), :cid),
                updatedAt = :time
            """,
            ExpressionAttributeValues={
                ":cid": {"L": [{"S": candidate_id}]},
                ":empty": {"L": []},
                ":time": {"S": now}
            }
        )

    except ClientError as e:
        return {
            "message": "Assignment failed",
            "error": str(e)
        }

    return {
        "message": "Assistant added to candidate successfully",
        "assistantId": assistant_id,
        "assistantName": assistant_name,
        "candidateId": candidate_id
    }

# lambda handler
def handler(event,context):

    cors=get_cors_headers()

    # preflight
    if event.get("httpMethod")=="OPTIONS":
        return{
            "statusCode":200,
            "headers":cors,
            "body":json.dumps({"message":"ok"})
        }

    try:

        admin,error=verify_admin_token(event)

        if error:
            return{
                "statusCode":401,
                "headers":cors,
                "body":json.dumps({"message":error})
            }

        if not event.get("body"):
            return {
                "statusCode": 400,
                "headers": cors,
                "body": json.dumps({"message": "Request body required"})
            }

        try:
            body = json.loads(event["body"])
        except json.JSONDecodeError:
            return {
                "statusCode": 400,
                "headers": cors,
                "body": json.dumps({"message": "Invalid JSON"})
            }

        assistant_id=body.get("assistantId")
        candidate_id=body.get("candidateId")

        if not assistant_id or not candidate_id:
            return{
                "statusCode":400,
                "headers":cors,
                "body":json.dumps({"message":"assistantId and candidateId required"})
            }

        result=assign_candidate(assistant_id,candidate_id)

        return{
            "statusCode":200,
            "headers":cors,
            "body":json.dumps(result)
        }

    except Exception as e:

        return{
            "statusCode":500,
            "headers":cors,
            "body":json.dumps({
                "message":"Internal server error",
                "error":str(e)
            })
        }
