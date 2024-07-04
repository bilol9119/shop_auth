from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import UserProfileViewSet

urlpatterns = [
    path('login/', UserProfileViewSet.as_view({"post": "login"})),
    path('login/refresh/', TokenRefreshView.as_view()),
    path('auth-me/', UserProfileViewSet.as_view({"get": "auth_me"})),
    path('user-update/', UserProfileViewSet.as_view({"patch": "profile_update"})),
]
