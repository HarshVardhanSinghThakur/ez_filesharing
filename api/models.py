# models.py
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import FileExtensionValidator


class User(AbstractUser):
    USER_TYPE_CHOICES = (
        ('OPS', 'Operations User'),
        ('CLIENT', 'Client User'),
    )
    user_type = models.CharField(max_length=10, choices=USER_TYPE_CHOICES)
    email_verified = models.BooleanField(default=False)
    verification_token = models.CharField(
        max_length=100, blank=True, null=True)


class UploadedFile(models.Model):
    ALLOWED_EXTENSIONS = ['pptx', 'docx', 'xlsx', 'pdf']

    file = models.FileField(
        upload_to='uploads/',
        validators=[FileExtensionValidator(
            allowed_extensions=ALLOWED_EXTENSIONS)]
    )
    uploader = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='uploaded_files')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    original_name = models.CharField(max_length=255)

    def __str__(self):
        return self.original_name


class DownloadToken(models.Model):
    token = models.CharField(max_length=100, unique=True)
    file = models.ForeignKey(UploadedFile, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
