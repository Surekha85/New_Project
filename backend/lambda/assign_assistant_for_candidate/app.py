
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
def assign_candidate(assistant_id,candidate_id):

    candidate_dynamo=assume_role(os.environ["CANDIDATE_DYNAMO_ROLE_ARN"])
    assistant_dynamo=assume_role(os.environ["ASSISTANT_DYNAMO_ROLE_ARN"])

    candidate_table=os.environ["CANDIDATES_TABLE"]
    assistant_table=os.environ["ASSISTANTS_TABLE"]

    # get candidate
    candidate=candidate_dynamo.get_item(
        TableName=candidate_table,
        Key={"jaa_candidate_id":{"S":candidate_id}}
    )
    if "Item" not in candidate:
        return{"message":"Candidate not found"}

    # get assistant
    assistant=assistant_dynamo.get_item(
        TableName=assistant_table,
        Key={"assistantId":{"S":assistant_id}}
    )
    if "Item" not in assistant:
        return{"message":"Assistant not found"}

    candidate_item=candidate["Item"]
    assistant_item=assistant["Item"]

    # check candidate already assigned
    existing_assistant=candidate_item.get("assistantAssignedTo",{}).get("S")

    if existing_assistant:
        if existing_assistant==assistant_id:
            return{"message":"Candidate already assigned to this assistant"}
        return{"message":"Candidate already assigned to another assistant"}

    # check assistant assigned list
    assigned_ids=[c["S"] for c in assistant_item.get("assigned_candidates",{}).get("L",[])]

    if candidate_id in assigned_ids:
        return{"message":"Candidate already present in assistant list"}

    now=datetime.utcnow().isoformat()

    try:

        # update candidate
        candidate_dynamo.update_item(
            TableName=candidate_table,
            Key={"jaa_candidate_id":{"S":candidate_id}},
            ConditionExpression="attribute_not_exists(assistantAssignedTo)",
            UpdateExpression="SET assistantAssignedTo=:aid,updatedAt=:time",
            ExpressionAttributeValues={
                ":aid":{"S":assistant_id},
                ":time":{"S":now}
            }
        )

        # update assistant
        assistant_dynamo.update_item(
            TableName=assistant_table,
            Key={"assistantId":{"S":assistant_id}},
            UpdateExpression="""SET assigned_candidates=
            list_append(if_not_exists(assigned_candidates,:empty),:cid),
            updatedAt=:time""",
            ExpressionAttributeValues={
                ":cid":{"L":[{"S":candidate_id}]},
                ":empty":{"L":[]},
                ":time":{"S":now}
            }
        )

    except ClientError as e:

        error_code=e.response['Error']['Code']

        # fallback safety (normally should not happen)
        if error_code=="ConditionalCheckFailedException":
            return{"message":"Assignment already processed"}

        return{
            "message":"Assignment failed",
            "error":str(e)
        }

    return{
        "message":"Candidate assigned successfully",
        "assistantId":assistant_id,
        "candidateId":candidate_id
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
