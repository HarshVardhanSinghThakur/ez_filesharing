# serializers.py
from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import User, UploadedFile, DownloadToken
from rest_framework_simplejwt.tokens import RefreshToken
import uuid
from datetime import datetime, timedelta

class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)
    
    def validate(self, data):
        user = authenticate(username=data['username'], password=data['password'])
        if not user:
            raise serializers.ValidationError("Invalid credentials")
        if user.user_type == 'CLIENT' and not user.email_verified:
            raise serializers.ValidationError("Email not verified")
        return user

class UserSignupSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'password', 'email', 'first_name', 'last_name']
        extra_kwargs = {'password': {'write_only': True}}
    
    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            password=validated_data['password'],
            email=validated_data['email'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            user_type='CLIENT',
            email_verified=False,
            verification_token=str(uuid.uuid4())
        )
        return user

class FileUploadSerializer(serializers.ModelSerializer):
    class Meta:
        model = UploadedFile
        fields = ['file']
    
    def validate_file(self, value):
        if not value.name.lower().endswith(('.pptx', '.docx', '.xlsx', '.pdf')):
            raise serializers.ValidationError("Only pptx, docx, pdf and xlsx files are allowed.")
        return value

class FileListSerializer(serializers.ModelSerializer):
    class Meta:
        model = UploadedFile
        fields = ['id', 'original_name', 'uploaded_at']

class DownloadTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = DownloadToken
        fields = ['token', 'expires_at']