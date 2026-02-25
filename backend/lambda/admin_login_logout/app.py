import json
import boto3
import hashlib
import jwt
import re
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

def get_cors_headers():
    """Return CORS headers based on stage"""
    stage = os.getenv('STAGE', 'prod').lower()
    origin = {
        'beta': 'https://beta.jobsyme.com',
        'gamma': 'https://gamma.jobsyme.com'
    }.get(stage, 'https://www.jobsyme.com')

    return {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
        'Access-Control-Allow-Credentials': 'true'
    }

def handler(event, context):
    """Admin Portal Login/Logout Lambda"""
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

        action = body.get('action', 'login').lower()

        if action == 'login':
            return handle_login(body, cors_headers)
        elif action == 'logout':
            return handle_logout(event, body, cors_headers)
        else:
            return error_response(400, "Invalid action. Use 'login' or 'logout'", cors_headers)

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return error_response(500, "Internal server error", cors_headers)

# ---------------------- Login Handler ----------------------

def handle_login(body, cors_headers):
    """Handle admin login"""
    email = body.get('email', '').strip().lower()
    password = body.get('password', '').strip()

    validation_error = validate_inputs(email, password)
    if validation_error:
        return error_response(400, validation_error, cors_headers)

    auth_result = authenticate_assistant(email, password)
    if not auth_result['success']:
        return error_response(401, auth_result['error'], cors_headers)

    assistant_data = auth_result['admin']

    token_result = generate_jwt_token(assistant_data)
    if not token_result['success']:
        return error_response(500, token_result['error'], cors_headers)

    logger.info(f"Admin login successful: {email}")
    update_last_login(assistant_data['adminId'])
    return {
        'statusCode': 200,
        'headers': cors_headers,
        'body': json.dumps({
            'message': 'Login successful',
            'token': token_result['token'],
            'expires_in': token_result['expires_in'],
            'user': {
                'adminId': assistant_data['adminId'],
                'email': assistant_data['email'],
                'first_name': assistant_data['first_name'],
                'last_name': assistant_data['last_name']
            }
        })
    }
# ---------------------- Update Last Login ----------------------

def update_last_login(assistant_id):
    """Update admin's last_login timestamp in DynamoDB"""
    try:
        table_name = os.getenv('ADMINS_TABLE')
        if not table_name:
            logger.warning('Assistants table not configured for last_login update')
            return
        dynamodb.update_item(
            TableName=table_name,
            Key={'adminId': {'S': assistant_id}},
            UpdateExpression='SET last_login = :ts',
            ExpressionAttributeValues={':ts': {'S': datetime.utcnow().isoformat() + 'Z'}}
        )
        logger.info(f"Updated last_login for adminId: {assistant_id}")
    except Exception as e:
        logger.warning(f"Failed to update last_login for adminId {assistant_id}: {str(e)}")

# ---------------------- Logout Handler ----------------------

def handle_logout(event, body, cors_headers):
    """Handle admin logout"""
    # Get token from Authorization header
    auth_header = event.get('headers', {}).get('Authorization', '')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return error_response(401, "Missing or invalid authorization header", cors_headers)

    token = auth_header.split(' ')[1]
    
    # Verify and decode token
    token_result = verify_jwt_token(token)
    if not token_result['success']:
        return error_response(401, token_result['error'], cors_headers)

    assistant_id = token_result['data']['adminId']
    logger.info(f"Admin logout successful: {assistant_id}")
    return {
        'statusCode': 200,
        'headers': cors_headers,
        'body': json.dumps({
            'message': 'Logout successful',
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
    }

# ---------------------- Helper Functions ----------------------

def validate_inputs(email, password):
    if not email:
        return "Email is required"
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return "Invalid email format"
    if not password:
        return "Password is required"
    return None

def authenticate_assistant(email, password):
    """Authenticate admin using DynamoDB table"""
    try:
        table_name = os.getenv('ADMINS_TABLE')
        if not table_name:
            return {'success': False, 'error': 'Assistants table not configured'}

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
        assistant_data = {
            'adminId': item.get('adminId', {}).get('S', ''),
            'email': item.get('email', {}).get('S', ''),
            'password_hash': item.get('password_hash', {}).get('S', ''),
            'first_name': item.get('first_name', {}).get('S', ''),
            'last_name': item.get('last_name', {}).get('S', '')
        }

        if not verify_password(password, assistant_data['password_hash']):
            return {'success': False, 'error': 'Invalid email or password'}

        return {'success': True, 'admin': assistant_data}

    except ClientError as e:
        return {'success': False, 'error': f"DynamoDB error: {e.response['Error']['Message']}"}
    except Exception as e:
        return {'success': False, 'error': f"Unexpected error: {str(e)}"}

def verify_password(password, stored_hash):
    salt = os.getenv('PASSWORD_SALT', 'jobsyme_secure_salt_2025')
    return hashlib.sha256((salt + password).encode()).hexdigest() == stored_hash

def generate_jwt_token(assistant_data):
    try:
        jwt_secret = get_jwt_secret()
        if not jwt_secret:
            return {'success': False, 'error': 'JWT secret not configured'}

        expires_in_seconds = int(os.getenv('JWT_EXPIRES_IN_SECONDS', '1209600'))
        expiration = datetime.utcnow() + timedelta(seconds=expires_in_seconds)

        payload = {
            'adminId': assistant_data['adminId'],
            'email': assistant_data['email'],
            'user_type': 'admin',
            'first_name': assistant_data['first_name'],
            'last_name': assistant_data['last_name'],
            'iat': int(datetime.utcnow().timestamp()),
            'exp': int(expiration.timestamp())
        }

        token = jwt.encode(payload, jwt_secret, algorithm='HS256')
        return {'success': True, 'token': token, 'expires_in': expires_in_seconds}
    except Exception as e:
        return {'success': False, 'error': f"Error generating JWT: {str(e)}"}

def verify_jwt_token(token):
    """Verify and decode JWT token"""
    try:
        jwt_secret = get_jwt_secret()
        if not jwt_secret:
            return {'success': False, 'error': 'JWT secret not configured'}

        payload = jwt.decode(token, jwt_secret, algorithms=['HS256'])
        return {'success': True, 'data': payload}
    except jwt.ExpiredSignatureError:
        return {'success': False, 'error': 'Token has expired'}
    except jwt.InvalidTokenError as e:
        return {'success': False, 'error': f'Invalid token: {str(e)}'}
    except Exception as e:
        return {'success': False, 'error': f"Error verifying token: {str(e)}"}

def get_jwt_secret():
    secret_name = os.getenv('JWT_SECRET_NAME')
    logger.info(f"JWT_SECRET_NAME env: {secret_name}")
    if not secret_name:
        logger.error("JWT_SECRET_NAME environment variable is not set.")
        return None
    try:
        response = secrets_client.get_secret_value(SecretId=secret_name)
        logger.info(f"Secret fetch response: {response}")
        secret_data = json.loads(response['SecretString'])
        logger.info(f"Secret data loaded: {secret_data}")
        return secret_data.get('jwt_secret')
    except Exception as e:
        logger.error(f"Error fetching JWT secret: {str(e)}")
        return None

def error_response(status_code, message, headers):
    return {
        'statusCode': status_code,
        'headers': headers,
        'body': json.dumps({'error': message, 'timestamp': datetime.utcnow().isoformat() + 'Z'})
    }



# {
#   "httpMethod": "POST",
#   "headers": {
#     "Content-Type": "application/json"
#   },
#   "body": "{\"action\": \"login\", \"email\": \"admin@example.com\", \"password\": \"password123\"}"
# }



# {
#   "httpMethod": "POST",
#   "headers": {
#     "Content-Type": "application/json",
#     "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhc3Npc3RhbnRJZCI6IjEyMyIsImVtYWlsIjoiYXNzaXN0YW50QGV4YW1wbGUuY29tIiwiZmlyc3RfbmFtZSI6IkpvaG4iLCJsYXN0X25hbWUiOiJEb2UiLCJpYXQiOjE3MDk3ODEwMDAsImV4cCI6MTcwOTc5NzQwMH0.signature"
#   },
#   "body": "{\"action\": \"logout\"}"
# }