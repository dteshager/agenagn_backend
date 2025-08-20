# AWS S3 Setup Guide for AgenagnPhone

This guide will help you configure AWS S3 for image uploads in your AgenagnPhone application.

## Prerequisites

1. AWS Account
2. EC2 instance named 'agenagn_backend' (already created)
3. S3 bucket named 'agenagn-uploads' (already created)

## Setup Steps

### 1. Configure S3 Bucket Permissions

#### Option A: Using S3 Bucket Policy (Recommended for production)

1. Go to AWS S3 Console
2. Select your bucket `agenagn-uploads`
3. Go to "Permissions" tab
4. Edit "Bucket policy" and add:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PublicReadGetObject",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::agenagn-uploads/*"
        },
        {
            "Sid": "AllowEC2Upload",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::YOUR_ACCOUNT_ID:role/EC2-S3-Role"
            },
            "Action": [
                "s3:PutObject",
                "s3:PutObjectAcl",
                "s3:DeleteObject"
            ],
            "Resource": "arn:aws:s3:::agenagn-uploads/*"
        }
    ]
}
```

Replace `YOUR_ACCOUNT_ID` with your AWS account ID.

#### Option B: Using Access Control Lists (ACL)

1. In S3 bucket permissions, unblock "Block public access (bucket settings)"
2. Allow "Block public access to buckets and objects granted through new access control lists (ACLs)"

### 2. Configure IAM Role for EC2 (Recommended)

#### Create IAM Role:

1. Go to IAM Console → Roles → Create role
2. Select "AWS service" → "EC2"
3. Attach policy with these permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:PutObjectAcl",
                "s3:GetObject",
                "s3:DeleteObject"
            ],
            "Resource": "arn:aws:s3:::agenagn-uploads/*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": "arn:aws:s3:::agenagn-uploads"
        }
    ]
}
```

4. Name the role: `EC2-S3-AgenagnRole`
5. Attach this role to your EC2 instance `agenagn_backend`

### 3. Configure Environment Variables

#### Option A: Using IAM Role (Recommended for EC2)

If using IAM role, you only need to set:

```bash
export AWS_REGION=us-east-1
export AWS_S3_BUCKET=agenagn-uploads
```

#### Option B: Using Access Keys

If not using IAM role, create access keys:

1. Go to IAM Console → Users → Create user
2. Attach the S3 policy from step 2
3. Create access keys
4. Set environment variables:

```bash
export AWS_ACCESS_KEY_ID=your-access-key-id
export AWS_SECRET_ACCESS_KEY=your-secret-access-key
export AWS_REGION=us-east-1
export AWS_S3_BUCKET=agenagn-uploads
```

### 4. Update Your EC2 Instance

1. SSH into your EC2 instance:
```bash
ssh -i your-key.pem ec2-user@your-ec2-ip
```

2. Navigate to your application directory:
```bash
cd /path/to/your/agenagn/backend
```

3. Set environment variables (add to ~/.bashrc for persistence):
```bash
echo 'export AWS_REGION=us-east-1' >> ~/.bashrc
echo 'export AWS_S3_BUCKET=agenagn-uploads' >> ~/.bashrc
source ~/.bashrc
```

4. Install boto3 if not already installed:
```bash
pip install boto3
```

5. Run the database migration:
```bash
python migrate_add_s3_key.py
```

6. Test S3 connection:
```bash
curl http://your-ec2-ip:5000/api/test-s3
```

### 5. CORS Configuration for S3 (if accessing from web)

If you plan to access S3 directly from frontend:

1. Go to S3 bucket → Permissions → CORS
2. Add this configuration:

```json
[
    {
        "AllowedHeaders": ["*"],
        "AllowedMethods": ["GET", "PUT", "POST", "DELETE"],
        "AllowedOrigins": ["*"],
        "ExposeHeaders": ["ETag"]
    }
]
```

## Testing

### 1. Test S3 Connection

Make a GET request to test the connection:
```bash
curl http://your-backend-url/api/test-s3
```

Expected response:
```json
{
    "success": true,
    "message": "Successfully connected to S3 bucket: agenagn-uploads",
    "bucket": "agenagn-uploads",
    "region": "us-east-1"
}
```

### 2. Test Image Upload

Create a post with an image through your app and verify:
1. Image appears in S3 bucket
2. Image URL in database starts with `https://agenagn-uploads.s3.us-east-1.amazonaws.com/`
3. Image loads in the app

## Troubleshooting

### Common Issues:

1. **403 Forbidden Error**: Check IAM permissions and bucket policy
2. **NoCredentialsError**: Ensure IAM role is attached or environment variables are set
3. **NoSuchBucket**: Verify bucket name and region
4. **Images not loading**: Check bucket public access settings

### Debug Steps:

1. Check IAM role attachment:
```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

2. Test AWS CLI (if installed):
```bash
aws s3 ls s3://agenagn-uploads/
```

3. Check application logs for detailed error messages

## Migration from Local Storage

If you have existing images in local storage, you can migrate them:

1. Create a migration script to upload existing images to S3
2. Update database records with new S3 URLs
3. Remove local image files after successful migration

## Security Best Practices

1. Use IAM roles instead of access keys when possible
2. Implement least privilege access
3. Enable S3 server-side encryption
4. Monitor S3 access logs
5. Set up S3 lifecycle policies for cost optimization

## Cost Optimization

1. Use S3 Standard-IA for images older than 30 days
2. Enable S3 Intelligent-Tiering
3. Set up lifecycle policies to delete old images
4. Monitor S3 costs in AWS Cost Explorer
