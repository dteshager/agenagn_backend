# Production Deployment Checklist

## Pre-Deployment Security Checks

### ✅ Environment Variables (.env file)
- [ ] `FLASK_ENV=production` is set
- [ ] `JWT_SECRET_KEY` is set to a strong random value (32+ characters)
  - Generate: `python -c "import secrets; print(secrets.token_urlsafe(32))"`
- [ ] `ALLOWED_ORIGINS` is set to specific domains (NOT `*`)
  - Example: `ALLOWED_ORIGINS=https://api.dteshager.com,https://dteshager.com`
- [ ] `DATABASE_URL` is set (if using PostgreSQL/MySQL, not SQLite)
- [ ] `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` are set
- [ ] `GOOGLE_REDIRECT_URI` points to your production API domain
- [ ] Email credentials are configured (SMTP settings)
- [ ] AWS S3 credentials are configured (if using IAM role, can omit)

### ✅ Security
- [ ] `.env` file is in `.gitignore` (NEVER commit secrets)
- [ ] No hardcoded passwords or API keys in code
- [ ] Database passwords are strong
- [ ] CORS is restricted to specific domains
- [ ] Debug mode is disabled (`debug=False`)

### ✅ Database
- [ ] Database is migrated and schema is up to date
- [ ] Database backups are configured
- [ ] If using SQLite, consider migrating to PostgreSQL for production

### ✅ Server Configuration
- [ ] Using Gunicorn with eventlet (not Flask dev server)
- [ ] `SOCKETIO_ASYNC_MODE=eventlet` in .env
- [ ] Server is configured to run on appropriate host/port
- [ ] SSL/HTTPS is configured (via nginx/reverse proxy)

## Deployment Steps

### 1. EC2 Instance Setup
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python 3 and pip
sudo apt install python3 python3-pip python3-venv -y

# Install nginx (for reverse proxy)
sudo apt install nginx -y

# Install PostgreSQL (recommended over SQLite)
sudo apt install postgresql postgresql-contrib -y
```

### 2. Application Setup
```bash
# Clone repository
cd /var/www  # or your preferred directory
git clone <your-repo-url> agenagn-backend
cd agenagn-backend/Backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create .env file with production values
nano .env  # Add all required environment variables
```

### 3. Database Setup (if using PostgreSQL)
```bash
# Create database and user
sudo -u postgres psql
CREATE DATABASE agenagn_db;
CREATE USER agenagn_user WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE agenagn_db TO agenagn_user;
\q

# Update DATABASE_URL in .env
# DATABASE_URL=postgresql://agenagn_user:your_secure_password@localhost/agenagn_db
```

### 4. Gunicorn Setup
```bash
# Test Gunicorn works
gunicorn -k eventlet -w 1 -b 127.0.0.1:5000 app:app

# Create systemd service (optional but recommended)
sudo nano /etc/systemd/system/agenagn-backend.service
```

Add this to the service file:
```ini
[Unit]
Description=Agenagn Flask Backend
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/agenagn-backend/Backend
Environment="PATH=/var/www/agenagn-backend/Backend/venv/bin"
ExecStart=/var/www/agenagn-backend/Backend/venv/bin/gunicorn -k eventlet -w 1 -b 127.0.0.1:5000 app:app

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start service
sudo systemctl enable agenagn-backend
sudo systemctl start agenagn-backend
sudo systemctl status agenagn-backend
```

### 5. Nginx Configuration
```bash
sudo nano /etc/nginx/sites-available/agenagn-api
```

Add configuration:
```nginx
server {
    listen 80;
    server_name api.dteshager.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket support for SocketIO
    location /socket.io {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

```bash
# Enable site and test
sudo ln -s /etc/nginx/sites-available/agenagn-api /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### 6. SSL Certificate (Let's Encrypt)
```bash
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d api.dteshager.com
```

### 7. Firewall Configuration
```bash
# Allow SSH, HTTP, HTTPS
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

### 8. Create Admin User
```bash
cd /var/www/agenagn-backend/Backend
source venv/bin/activate
python create_admin_user.py
```

## Post-Deployment Verification

- [ ] API responds at `https://api.dteshager.com/api/...`
- [ ] SSL certificate is valid
- [ ] CORS headers are correct
- [ ] Admin login works
- [ ] Database connections work
- [ ] File uploads to S3 work
- [ ] Email sending works
- [ ] WebSocket connections work (if using SocketIO)
- [ ] Error logs are being captured
- [ ] Server restarts automatically after reboot

## Monitoring

- [ ] Set up log rotation
- [ ] Monitor server resources (CPU, memory, disk)
- [ ] Set up alerts for errors
- [ ] Regular database backups

## Security Best Practices

1. **Never commit `.env` files** - Always use `.gitignore`
2. **Use strong secrets** - Generate random tokens for JWT_SECRET_KEY
3. **Restrict CORS** - Never use `*` in production
4. **Use HTTPS** - Always use SSL certificates
5. **Keep dependencies updated** - Regularly update packages
6. **Use PostgreSQL** - More reliable than SQLite for production
7. **Set up backups** - Regular database backups
8. **Monitor logs** - Check for errors and suspicious activity
9. **Limit SSH access** - Use key-based authentication
10. **Use firewall** - Only open necessary ports

## Rollback Plan

If something goes wrong:
1. Stop the service: `sudo systemctl stop agenagn-backend`
2. Revert code changes: `git checkout <previous-commit>`
3. Restore database from backup if needed
4. Restart service: `sudo systemctl start agenagn-backend`

## Support

For issues:
- Check logs: `sudo journalctl -u agenagn-backend -f`
- Check nginx logs: `sudo tail -f /var/log/nginx/error.log`
- Check application logs: Check your logging configuration

