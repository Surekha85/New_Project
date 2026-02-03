import boto3
import os
import json

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(os.environ["CANDIDATES_TABLE"])

def handler(event, context):
    candidate_id = event["requestContext"]["authorizer"]["candidateId"]

    response = table.get_item(
        Key={"candidateId": candidate_id}
    )

    if "Item" not in response:
        return {
            "statusCode": 404,
            "body": json.dumps({"message": "Candidate not found"})
        }

    return {
        "statusCode": 200,
        "body": json.dumps(response["Item"])
    }
