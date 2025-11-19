from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import RegisterSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.middleware.csrf import get_token
from django.conf import settings  # Agrega esta línea
from django.contrib.auth.models import User
import requests
from decouple import config

from django.middleware.csrf import get_token
from rest_framework.views import APIView

class CSRFTokenView(APIView):
    authentication_classes = []  # Permitir sin autenticación
    permission_classes = []  # Permitir acceso libre

    def get(self, request):
        csrf_token = get_token(request)
        return Response({'csrftoken': csrf_token})


class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Usuario registrado con éxito"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = authenticate(email=email, password=password)
        if user is not None:
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)

            response = Response({"message": "Inicio de sesión exitoso"})

            # Access token
            response.set_cookie(
                key=settings.SIMPLE_JWT['AUTH_COOKIE'],
                value=access_token,
                httponly=True,
                samesite=settings.SIMPLE_JWT.get('AUTH_COOKIE_SAMESITE', 'Lax'),
                secure=settings.SIMPLE_JWT.get('AUTH_COOKIE_SECURE', False),
                path=settings.SIMPLE_JWT.get('AUTH_COOKIE_PATH', '/'),
            )

            # Refresh token
            response.set_cookie(
                key=settings.SIMPLE_JWT.get('AUTH_COOKIE_REFRESH', 'jwt-refresh'),
                value=refresh_token,
                httponly=True,
                samesite=settings.SIMPLE_JWT.get('AUTH_COOKIE_SAMESITE', 'Lax'),
                secure=settings.SIMPLE_JWT.get('AUTH_COOKIE_SECURE', False),
                path=settings.SIMPLE_JWT.get('AUTH_COOKIE_PATH', '/'),
            )

            return response

        return Response({"error": "Credenciales inválidas"}, status=status.HTTP_401_UNAUTHORIZED)

    
class LogoutView(APIView):
    def post(self, request):
        response = Response({"message": "Logout exitoso"})

        # Elimina las cookies usando solo los argumentos válidos para tu versión de Django
        response.delete_cookie(
            key=settings.SIMPLE_JWT['AUTH_COOKIE'],
            path=settings.SIMPLE_JWT.get('AUTH_COOKIE_PATH', '/'),
            samesite=settings.SIMPLE_JWT.get('AUTH_COOKIE_SAMESITE', 'Lax')
        )
        response.delete_cookie('access_token', path='/', samesite='Lax')
        response.delete_cookie('jwt-auth', path='/', samesite='Lax')

        response.status_code = 200
        return response
    

from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.utils.text import slugify
import uuid

@method_decorator(csrf_exempt, name='dispatch')
class GoogleOAuthView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        code = request.data.get('code')
        GOOGLE_CLIENT_ID = config("GOOGLE_CLIENT_ID")
        GOOGLE_CLIENT_SECRET = config("GOOGLE_CLIENT_SECRET")
        if not code:
            return Response({"error": "Authorization code no recibido"}, status=status.HTTP_400_BAD_REQUEST)
        

        # Intercambiar authorization code por tokens
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,  # asegúrate de que coincida con el frontend
            "grant_type": "authorization_code",
        }

        token_response = requests.post(token_url, data=data)
        if token_response.status_code != 200:
            return Response({"error": "Error al obtener tokens de Google"}, status=status.HTTP_400_BAD_REQUEST)

        tokens = token_response.json()
        id_token = tokens.get("id_token")
        if not id_token:
            return Response({"error": "ID token no recibido"}, status=status.HTTP_400_BAD_REQUEST)

        # Verificar id_token con Google
        verify_url = f"https://oauth2.googleapis.com/tokeninfo?id_token={id_token}"
        verify_response = requests.get(verify_url)
        if verify_response.status_code != 200:
            return Response({"error": "ID token inválido"}, status=status.HTTP_400_BAD_REQUEST)

        user_info = verify_response.json()
        email = user_info.get('email')
        if not email:
            return Response({"error": "No se encontró correo en el token"}, status=status.HTTP_400_BAD_REQUEST)

        username = slugify(email.split("@")[0]) or str(uuid.uuid4())[:8]

        user, created = User.objects.get_or_create(email=email, defaults={"username": username})
        if created:
            user.set_unusable_password()
            user.save()

        # JWT interno (SimpleJWT)
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        response = Response({"message": "Inicio de sesión exitoso"})

        # Access token
        response.set_cookie(
            key=settings.SIMPLE_JWT['AUTH_COOKIE'],
            value=access_token,
            httponly=True,
            samesite=settings.SIMPLE_JWT.get('AUTH_COOKIE_SAMESITE', 'Lax'),
            secure=settings.SIMPLE_JWT.get('AUTH_COOKIE_SECURE', False),
            path=settings.SIMPLE_JWT.get('AUTH_COOKIE_PATH', '/'),
        )

        # Refresh token
        response.set_cookie(
            key=settings.SIMPLE_JWT.get('AUTH_COOKIE_REFRESH', 'jwt-refresh'),
            value=refresh_token,
            httponly=True,
            samesite=settings.SIMPLE_JWT.get('AUTH_COOKIE_SAMESITE', 'Lax'),
            secure=settings.SIMPLE_JWT.get('AUTH_COOKIE_SECURE', False),
            path=settings.SIMPLE_JWT.get('AUTH_COOKIE_PATH', '/'),
        )

        return response


    
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import UntypedToken

class DebugUserView(APIView):
    def get(self, request):
        try:
            token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE'])
            if not token:
                return Response({"error": "No se recibió token"}, status=401)
            
            validated_token = UntypedToken(token)
            user = JWTAuthentication().get_user(validated_token)
            
            return Response({
                "user_id": user.id,
                "email": user.email,
                "username": user.username,
                "token_valid": True,
                "token": token 
            })
        except (InvalidToken, TokenError) as e:
            return Response({"error": str(e)}, status=401)
        except Exception as e:
            return Response({"error": "Error interno"}, status=500)

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken

class TokenObtainPairView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")
        user = authenticate(email=email, password=password)

        if not user:
            return Response({"error": "Credenciales inválidas"}, status=401)

        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        response = Response({"message": "Token emitido"})

        response.set_cookie(
            key=settings.SIMPLE_JWT['AUTH_COOKIE'],
            value=access_token,
            httponly=True,
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE'],
            path=settings.SIMPLE_JWT['AUTH_COOKIE_PATH'],
        )
        response.set_cookie(
            key=settings.SIMPLE_JWT.get('AUTH_COOKIE_REFRESH', 'jwt-refresh'),
            value=refresh_token,
            httponly=True,
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE'],
            path=settings.SIMPLE_JWT['AUTH_COOKIE_PATH'],
        )
        return response


class TokenRefreshView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        refresh_token = request.COOKIES.get('jwt-refresh')
        if not refresh_token:
            return Response({"error": "No se encontró refresh token"}, status=401)

        try:
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)
        except (TokenError, InvalidToken):
            return Response({"error": "Refresh token inválido o expirado"}, status=401)

        response = Response({"message": "Token renovado"})
        response.set_cookie(
            key=settings.SIMPLE_JWT['AUTH_COOKIE'],
            value=access_token,
            httponly=True,
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE'],
            path=settings.SIMPLE_JWT['AUTH_COOKIE_PATH'],
        )
        return response
