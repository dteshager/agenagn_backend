import boto3
import os
import uuid
from botocore.exceptions import ClientError, NoCredentialsError
from werkzeug.utils import secure_filename
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# S3 Configuration
S3_BUCKET = os.getenv('AWS_S3_BUCKET', 'agenagn-uploads')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-2')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# Initialize S3 client
def get_s3_client():
    """Initialize and return S3 client with credentials from environment or IAM role"""
    try:
        # Try to use environment variables first
        aws_access_key = os.getenv('AWS_ACCESS_KEY_ID')
        aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
        
        if aws_access_key and aws_secret_key:
            # Use explicit credentials
            s3_client = boto3.client(
                's3',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=AWS_REGION
            )
            logger.info("S3 client initialized with environment credentials")
        else:
            # Use IAM role (for EC2 instances)
            s3_client = boto3.client('s3', region_name=AWS_REGION)
            logger.info("S3 client initialized with IAM role")
            
        return s3_client
    except Exception as e:
        logger.error(f"Failed to initialize S3 client: {str(e)}")
        raise

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_s3_key(filename, folder='uploads'):
    """Generate a unique S3 key for the file"""
    secure_name = secure_filename(filename)
    unique_filename = f"{uuid.uuid4()}_{secure_name}"
    return f"{folder}/{unique_filename}"

def upload_file_to_s3(file_obj, filename, folder='uploads'):
    """
    Upload a file to S3 bucket
    
    Args:
        file_obj: File object to upload
        filename: Original filename
        folder: S3 folder/prefix (default: 'uploads')
    
    Returns:
        dict: Success response with S3 URL and key, or error response
    """
    try:
        # Validate file
        if not allowed_file(filename):
            return {
                'success': False,
                'error': 'File type not allowed'
            }
        
        # Generate S3 key
        s3_key = generate_s3_key(filename, folder)
        
        # Get S3 client
        s3_client = get_s3_client()
        
        # Determine content type
        content_type = 'image/jpeg'  # default
        if filename.lower().endswith('.png'):
            content_type = 'image/png'
        elif filename.lower().endswith('.gif'):
            content_type = 'image/gif'
        elif filename.lower().endswith('.webp'):
            content_type = 'image/webp'
        
        # Upload file to S3 (no ACL: many buckets enforce Object Ownership and disallow ACLs)
        s3_client.upload_fileobj(
            file_obj,
            S3_BUCKET,
            s3_key,
            ExtraArgs={
                'ContentType': content_type
            }
        )
        
        # Generate public URL
        s3_url = f"https://{S3_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{s3_key}"
        
        logger.info(f"Successfully uploaded file to S3: {s3_url}")
        
        return {
            'success': True,
            's3_url': s3_url,
            's3_key': s3_key,
            'filename': filename
        }
        
    except NoCredentialsError:
        logger.error("AWS credentials not found")
        return {
            'success': False,
            'error': 'AWS credentials not configured'
        }
    except ClientError as e:
        logger.error(f"S3 client error: {str(e)}")
        return {
            'success': False,
            'error': f'S3 upload failed: {str(e)}'
        }
    except Exception as e:
        logger.error(f"Unexpected error during S3 upload: {str(e)}")
        return {
            'success': False,
            'error': f'Upload failed: {str(e)}'
        }

def delete_file_from_s3(s3_key):
    """
    Delete a file from S3 bucket
    
    Args:
        s3_key: S3 key of the file to delete
    
    Returns:
        dict: Success or error response
    """
    try:
        s3_client = get_s3_client()
        
        s3_client.delete_object(Bucket=S3_BUCKET, Key=s3_key)
        
        logger.info(f"Successfully deleted file from S3: {s3_key}")
        
        return {
            'success': True,
            'message': f'File deleted: {s3_key}'
        }
        
    except ClientError as e:
        logger.error(f"S3 client error while deleting: {str(e)}")
        return {
            'success': False,
            'error': f'S3 deletion failed: {str(e)}'
        }
    except Exception as e:
        logger.error(f"Unexpected error during S3 deletion: {str(e)}")
        return {
            'success': False,
            'error': f'Deletion failed: {str(e)}'
        }

def test_s3_connection():
    """
    Test S3 connection and bucket access
    
    Returns:
        dict: Connection test result
    """
    try:
        s3_client = get_s3_client()
        
        # Try to list bucket contents (just to test connection)
        response = s3_client.list_objects_v2(Bucket=S3_BUCKET, MaxKeys=1)
        
        logger.info(f"S3 connection test successful for bucket: {S3_BUCKET}")
        
        return {
            'success': True,
            'message': f'Successfully connected to S3 bucket: {S3_BUCKET}',
            'bucket': S3_BUCKET,
            'region': AWS_REGION
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchBucket':
            logger.error(f"S3 bucket does not exist: {S3_BUCKET}")
            return {
                'success': False,
                'error': f'S3 bucket does not exist: {S3_BUCKET}'
            }
        else:
            logger.error(f"S3 connection test failed: {str(e)}")
            return {
                'success': False,
                'error': f'S3 connection failed: {str(e)}'
            }
    except Exception as e:
        logger.error(f"S3 connection test error: {str(e)}")
        return {
            'success': False,
            'error': f'Connection test failed: {str(e)}'
        }
