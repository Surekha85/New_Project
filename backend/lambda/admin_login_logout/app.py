import json
import boto3
import jwt
import re
import bcrypt
import os
import logging
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

# Logger setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
dynamodb = boto3.client('dynamodb')
secrets_client = boto3.client('secretsmanager')

JWT_SECRET_CACHE = None


def get_cors_headers():
    """Return CORS headers based on stage"""
    origin = 'http://localhost:3000'

    return {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
        'Access-Control-Allow-Credentials': 'true'
    }

def handler(event, context):
    """Admin Portal Login Lambda"""
    logger.info("Admin request received")
    cors_headers = get_cors_headers()

    try:
        if event.get('httpMethod') == 'OPTIONS':
            return {'statusCode': 200, 'headers': cors_headers, 'body': json.dumps({'message': 'CORS preflight'})}

        # Parse request body
        if 'body' not in event or not event['body']:
            return error_response(400, "Missing request body", cors_headers)

        try:
            body = json.loads(event['body'])
        except json.JSONDecodeError:
            return error_response(400, "Invalid JSON", cors_headers)

        """Handle admin login"""
        email = body.get('email', '').strip().lower()
        password = body.get('password', '').strip()

        validation_error = validate_inputs(email, password)
        if validation_error:
            return error_response(400, validation_error, cors_headers)

        auth_result = authenticate_admin(email, password)
        if not auth_result['success']:
            return error_response(401, auth_result['error'], cors_headers)

        admin_data = auth_result['admin']

        token_result = generate_jwt_token(admin_data)
        if not token_result['success']:
            return error_response(500, token_result['error'], cors_headers)

        logger.info(f"Admin login successful: {email}")
        update_last_login(admin_data['adminId'])
        return {
            'statusCode': 200,
            'headers': cors_headers,
            'body': json.dumps({
                'message': 'Login successful',
                'token': token_result['token'],
                'expires_in': token_result['expires_in'],
                'user': {
                    'adminId': admin_data['adminId'],
                    'email': admin_data['email'],
                    'first_name': admin_data['first_name'],
                    'last_name': admin_data['last_name']
                }
            })
        }

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return error_response(500, "Internal server error", cors_headers)


# ---------------------- Update Last Login ----------------------

def update_last_login(admin_id):
    """Update admin's last_login timestamp in DynamoDB"""
    try:
        table_name = os.getenv('ADMINS_TABLE')
        if not table_name:
            logger.warning('admins table not configured for last_login update')
            return
        dynamodb.update_item(
            TableName=table_name,
            Key={'adminId': {'S': admin_id}},
            UpdateExpression='SET last_login = :ts',
            ExpressionAttributeValues={':ts': {'S': datetime.utcnow().isoformat() + 'Z'}}
        )
        logger.info(f"Updated last_login for adminId: {admin_id}")
    except Exception as e:
        logger.warning(f"Failed to update last_login for adminId {admin_id}: {str(e)}")



# ---------------------- Helper Functions ----------------------

def validate_inputs(email, password):
    if not email:
        return "Email is required"
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return "Invalid email format"
    if not password:
        return "Password is required"
    return None

def authenticate_admin(email, password):
    """Authenticate admin using DynamoDB table"""
    try:
        table_name = os.getenv('ADMINS_TABLE')
        if not table_name:
            return {'success': False, 'error': 'admins table not configured'}

        # Query by email using GSI
        response = dynamodb.query(
            TableName=table_name,
            IndexName='email-index',
            KeyConditionExpression='email = :email',
            ExpressionAttributeValues={':email': {'S': email}}
        )

        if not response.get('Items'):
            return {'success': False, 'error': 'Invalid email or password'}

        item = response['Items'][0]
        admin_data = {
            'adminId': item.get('adminId', {}).get('S', ''),
            'email': item.get('email', {}).get('S', ''),
            'password_hash': item.get('password_hash', {}).get('S', ''),
            'first_name': item.get('first_name', {}).get('S', ''),
            'last_name': item.get('last_name', {}).get('S', '')
        }

        if not verify_password(password, admin_data['password_hash']):
            return {'success': False, 'error': 'Invalid email or password'}

        return {'success': True, 'admin': admin_data}

    except ClientError as e:
        return {'success': False, 'error': f"DynamoDB error: {e.response['Error']['Message']}"}
    except Exception as e:
        return {'success': False, 'error': f"Unexpected error: {str(e)}"}

def verify_password(password, stored_hash):
    try:
        return bcrypt.checkpw(
            password.encode('utf-8'),
            stored_hash.encode('utf-8')
        )
    except Exception as e:
        logger.error(f"Password verification error: {str(e)}")
        return False


def generate_jwt_token(admin_data):
    try:
        jwt_secret = get_jwt_secret()
        if not jwt_secret:
            return {'success': False, 'error': 'JWT secret not configured'}

        expires_in_seconds = int(os.getenv('JWT_EXPIRES_IN_SECONDS', '86400'))
        expiration = datetime.utcnow() + timedelta(seconds=expires_in_seconds)

        payload = {
            'adminId': admin_data['adminId'],
            'email': admin_data['email'],
            'user_type': 'admin',
            'first_name': admin_data['first_name'],
            'last_name': admin_data['last_name'],
            'iat': int(datetime.utcnow().timestamp()),
            'exp': int(expiration.timestamp())
        }

        token = jwt.encode(payload, jwt_secret, algorithm='HS256')
        return {'success': True, 'token': token, 'expires_in': expires_in_seconds}
    except Exception as e:
        return {'success': False, 'error': f"Error generating JWT: {str(e)}"}


# Fetch JWT secret from AWS Secrets Manager
def get_jwt_secret():
    global JWT_SECRET_CACHE

    # Return cached secret if available
    if JWT_SECRET_CACHE:
        return JWT_SECRET_CACHE 

    secret_name = os.getenv('JWT_SECRET_NAME')
    if not secret_name:
        logger.error("JWT_SECRET_NAME environment variable is not set.")
        return None
    try:
        response = secrets_client.get_secret_value(SecretId=secret_name)
        secret_data = json.loads(response['SecretString'])
        JWT_SECRET_CACHE = secret_data.get("jwt_secret")
        return JWT_SECRET_CACHE

    except Exception as e:
        logger.error(f"Error fetching JWT secret: {str(e)}")
        return None


def error_response(status_code, message, headers):
    return {
        'statusCode': status_code,
        'headers': headers,
        'body': json.dumps({'error': message, 'timestamp': datetime.utcnow().isoformat() + 'Z'})
    }



{
  "httpMethod": "POST",
  "headers": {
    "Content-Type": "application/json"
  },
  "body": "{\"action\": \"login\", \"email\": \"john@example.com\", \"password\": \"Str0ngP@ssword!\"}"
}