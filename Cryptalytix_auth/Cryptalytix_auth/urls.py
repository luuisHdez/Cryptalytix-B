from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('auth_service.urls')),  # Elimina 'auth/' para que las rutas estén en la raíz
]
