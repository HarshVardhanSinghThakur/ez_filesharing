# urls.py
from django.urls import path
from .views import (
    LoginView,
    SignupView,
    VerifyEmailView,
    FileUploadView,
    FileListView,
    DownloadFileView,
    TokenDownloadView
)

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('signup/', SignupView.as_view(), name='signup'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify-email'),
    path('upload/', FileUploadView.as_view(), name='file-upload'),
    path('files/', FileListView.as_view(), name='file-list'),
    path('download-file/<int:file_id>/', DownloadFileView.as_view(), name='download-file'),
    path('download/<str:token>/', TokenDownloadView.as_view(), name='token-download'),
]

