
# Secure File Sharing API

A Django REST API for secure file sharing between Ops and Client users with JWT authentication.

## Setup

1. **Install requirements**:
   ```bash
   pip install -r requirements.txt
Run migrations:

```bash
python manage.py makemigrations
python manage.py migrate
```
Create first Ops user (run in shell):
```bash
from api.models import User
User.objects.create_user(username="admin_ops", password="ops123", user_type="OPS", email_verified=True)
```
Run server:
```bash
python manage.py runserver
```
#API Endpoints

Authentication

Endpoint	Method	Description

/api/login/	POST	Login (returns JWT tokens)

/api/signup/	POST	Client signup (requires email verification)

/api/verify-email/	GET	Verify email with token

#File Operations
Endpoint	Method	Description	Access

/api/upload/	POST	Upload files (.docx, .xlsx, .pptx)	Ops only

/api/files/	GET	List all files	Client only

/api/download/<file_id>/	GET	Download file	Client only


#Usage Examples

Client Signup:
```bash
curl -X POST http://localhost:8000/api/signup/ \
-H "Content-Type: application/json" \
-d '{"username":"user1", "password":"pass123", "email":"user@example.com"}'
```
File Upload (Ops):

```bash
curl -X POST http://localhost:8000/api/upload/ \
-H "Authorization: Bearer <OPS_TOKEN>" \
-F "file=@report.docx"
```
File Download (Client):

```bash
curl -X GET http://localhost:8000/api/download/1/ \
-H "Authorization: Bearer <CLIENT_TOKEN>" \
--output report.docx
```
