from django.urls import path, include
from .views import DebugUserView, CSRFTokenView, RegisterView,LogoutView, LoginView, GoogleOAuthView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('google-oauth/', GoogleOAuthView.as_view(), name='google_oauth'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('debug-user/', DebugUserView.as_view(), name='debug_user'),
    path('csrf-token/', CSRFTokenView.as_view(), name='csrf_token'),
]

