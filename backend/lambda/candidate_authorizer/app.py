import json
import os
import jwt
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

secrets_client = boto3.client("secretsmanager")

JWT_SECRET_NAME = os.environ["JWT_SECRET_NAME"]

def handler(event, context):
    try:
        # 1. Get Authorization header
        auth_header = event.get("authorizationToken")
        if not auth_header:
            raise Exception("Missing Authorization header")

        if not auth_header.startswith("Bearer "):
            raise Exception("Invalid Authorization format")

        token = auth_header.replace("Bearer ", "")

        # 2. Get JWT secret
        jwt_secret = get_jwt_secret()
        if not jwt_secret:
            raise Exception("JWT secret not found")

        # 3. Decode & verify JWT
        decoded = jwt.decode(
            token,
            jwt_secret,
            algorithms=["HS256"]
        )

        # 4. Custom validations (VERY IMPORTANT)
        if decoded.get("user_type") != "candidate":
            raise Exception("Invalid user type")

        if decoded.get("email_verified") is not True:
            raise Exception("Email not verified")

        user_id = decoded.get("user_id")
        email = decoded.get("email")

        if not user_id or not email:
            raise Exception("Invalid token payload")

        # 5. Allow policy
        return {
            "principalId": user_id,
            "policyDocument": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Action": "execute-api:Invoke",
                    "Effect": "Allow",
                    "Resource": event["methodArn"]
                }]
            },
            "context": {
                "userId": user_id,
                "email": email,
                "userType": decoded.get("user_type")
            }
        }

    except Exception as e:
        logger.error(f"JWT Authorizer failed: {str(e)}")
        raise Exception("Unauthorized")


def get_jwt_secret():
    """Fetch JWT secret from Secrets Manager"""
    try:
        response = secrets_client.get_secret_value(
            SecretId=JWT_SECRET_NAME
        )
        secret_data = json.loads(response["SecretString"])
        return secret_data.get("jwt_secret")
    except Exception as e:
        logger.error(f"Failed to get JWT secret: {str(e)}")
        return None
