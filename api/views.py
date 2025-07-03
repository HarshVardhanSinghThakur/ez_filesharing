# views.py
from rest_framework import generics, permissions, status
from django.http import FileResponse
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import User, UploadedFile, DownloadToken
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import NotFound, PermissionDenied
from .serializers import (
    UserLoginSerializer,
    UserSignupSerializer,
    FileUploadSerializer,
    FileListSerializer,
    DownloadTokenSerializer
)
from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import get_object_or_404
import uuid
from datetime import datetime, timedelta
from rest_framework_simplejwt.tokens import RefreshToken


class LoginView(APIView):
    authentication_classes = []  
    permission_classes = []     
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data
        refresh = RefreshToken.for_user(user)

        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user_type': user.user_type
        }, status=status.HTTP_200_OK)
        # return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SignupView(generics.CreateAPIView):
    authentication_classes = []  
    permission_classes = [] 
    #queryset = User.objects.all()
    serializer_class = UserSignupSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = serializer.save()
        verification_token = user.verification_token
        
        # Build verification URL
        verification_url = f"http://localhost:8000/api/verify-email/?token={verification_token}"
        
        try:
            send_mail(
                'Verify Your Email',
                f'Click to verify: {verification_url}',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            return Response({
                "status": "success",
                "message": "User created. Verification email sent.",
                "verification_url": verification_url,  
                "token": verification_token           
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response({
                "status": "partial_success",
                "message": "User created but email failed to send",
                "verification_url": verification_url,
                "token": verification_token,
                "error": str(e)
            }, status=status.HTTP_201_CREATED)


class VerifyEmailView(APIView):
    authentication_classes = []  
    permission_classes = []
    def get(self, request):
        token = request.query_params.get('token')
        try:
            user = User.objects.get(verification_token=token)
            user.email_verified = True
            user.verification_token = None
            user.save()
            return Response({'message': 'Email verified successfully'})
        except User.DoesNotExist:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class FileUploadView(generics.CreateAPIView):
    serializer_class = FileUploadSerializer
    permission_classes = [permissions.IsAuthenticated]

    def check_permissions(self, request):
        super().check_permissions(request)
        if request.user.user_type != 'OPS':
            self.permission_denied(
                request,
                message="Only Ops users can upload files",
                code=status.HTTP_403_FORBIDDEN
            )

    def perform_create(self, serializer):
        file = serializer.validated_data['file']
        serializer.save(
            uploader=self.request.user,
            original_name=file.name
        )

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        return Response({
            'status': 'success',
            'filename': request.FILES['file'].name,
            'message': 'File uploaded successfully'
        }, status=status.HTTP_201_CREATED)

class FileListView(generics.ListAPIView):
    serializer_class = FileListSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return UploadedFile.objects.all()


class DownloadFileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, file_id):
        # Check if user is client
        if request.user.user_type != 'CLIENT':
            return Response(
                {'error': 'Only client users can download files'},
                status=status.HTTP_403_FORBIDDEN
            )

        file = get_object_or_404(UploadedFile, id=file_id)

        # Create download token
        token = str(uuid.uuid4())
        expires_at = datetime.now() + timedelta(hours=1)
        DownloadToken.objects.create(
            token=token,
            file=file,
            user=request.user,
            expires_at=expires_at
        )

        download_url = f"http://localhost:8000/api/download/{token}/"
        return Response({
            'download-link': download_url,
            'message': 'success'
        })


class TokenDownloadView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, token):
        try:
            # Find valid unused token
            download_token = DownloadToken.objects.get(
                token=token,
                expires_at__gt=datetime.now(),
                used=False
            )
            
            # Verify requesting user is the token owner
            if download_token.user != request.user:
                raise PermissionDenied("Unauthorized access")
            
            # Mark token as used
            download_token.used = True
            download_token.save()
            
  
            file = download_token.file.file
    
            response = FileResponse(
                file.open('rb'),
                as_attachment=True,
                filename=download_token.file.original_name
            )
            
            # Set appropriate content type
            if file.name.endswith('.docx'):
                response['Content-Type'] = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            elif file.name.endswith('.xlsx'):
                response['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            elif file.name.endswith('.pptx'):
                response['Content-Type'] = 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
            
            return response
            
        except DownloadToken.DoesNotExist:
            raise NotFound("Invalid or expired token")
