import json, os, boto3, bcrypt, jwt
from datetime import datetime, timedelta

table = boto3.resource("dynamodb").Table(os.environ["CANDIDATES_TABLE"])
JWT_SECRET = os.environ["JWT_SECRET"]

def handler(event, context):
    body = json.loads(event["body"])
    email = body["email"]
    password = body["password"]

    resp = table.scan(
        FilterExpression="email = :e",
        ExpressionAttributeValues={":e": email}
    )

    if not resp["Items"]:
        return {"statusCode": 401, "body": "Invalid credentials"}

    user = resp["Items"][0]

    if not bcrypt.checkpw(password.encode(), user["passwordHash"].encode()):
        return {"statusCode": 401, "body": "Invalid credentials"}

    token = jwt.encode(
        {
            "candidateId": user["candidateId"],
            "role": user["role"],
            "exp": datetime.utcnow() + timedelta(hours=1)
        },
        JWT_SECRET,
        algorithm="HS256"
    )

    return {
        "statusCode": 200,
        "body": json.dumps({"token": token})
    }
