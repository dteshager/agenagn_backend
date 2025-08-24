Email verification setup
========================

Set the following environment variables (e.g., in `Backend/.env`):

```
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USERNAME=apikey
SMTP_PASSWORD=YOUR_SENDGRID_API_KEY
SMTP_USE_TLS=true
EMAIL_FROM=no-reply@yourdomain.com
```

Then restart the backend. On registration, the server creates a code and sends it to the email. If sending fails, the API still returns 201 and includes `email_error` and the code so you can verify manually or tap "Resend code" from the app after fixing SMTP.


