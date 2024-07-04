from rest_framework import status
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.contrib.auth.hashers import make_password
from datetime import datetime

from .models import User, OTPRegisterResend, OTPSetPassword
from .serializers import (UserSerializer,
                          OTPRegisterResendSerializer, OTPSetPasswordSerializer)
from .utils import (check_code_expire, checking_number_of_otp,
                    send_otp_code_telegram, check_resend_otp_code, check_token_expire)


class UserProfileViewSet(ViewSet):
    @swagger_auto_schema(
        operation_description="Log in ",
        operation_summary="Login verified user",
        responses={200: ' returns access and refresh tokens'},
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING, maxLength=12),
                'password': openapi.Schema(type=openapi.TYPE_STRING, maxLength=50),
            },
            required=['username', 'password']
        ),
        tags=['auth']

    )
    def login(self, request, *args, **kwargs):
        data = request.data
        user = User.objects.filter(username=data.get('username')).first()
        if not user:
            return Response(data={'error': 'user with this username not found', 'ok': False},
                            status=status.HTTP_400_BAD_REQUEST)
        if not user.is_verified:
            return Response(data={"error": "user is not verified", "ok": False}, status=status.HTTP_400_BAD_REQUEST)

        if user.check_password(data.get('password')):
            token = RefreshToken.for_user(user)
            return Response(data={'access': str(token.access_token), 'refresh': str(token)}, status=status.HTTP_200_OK)
        return Response(data={'error': 'password is incorrect', 'ok': False}, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_description="User detail",
        operation_summary="Returns user detail by token",
        responses={200: UserSerializer()},
        tags=['auth']

    )
    def auth_me(self, request, *args, **kwargs):
        if not (request.user.is_authenticated and request.user.is_verified):
            return Response({"Error": "Please authenticate "}, status.HTTP_401_UNAUTHORIZED)
        token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
        token = AccessToken(token)
        user_id = token.payload.get('user_id')
        serializer = UserSerializer(User.objects.filter(id=user_id).first())
        return Response(serializer.data, status.HTTP_200_OK)

    @swagger_auto_schema(
        operation_description="Profile update",
        operation_summary="Register new users",
        responses={201: OTPRegisterResendSerializer()},
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'first_name': openapi.Schema(type=openapi.TYPE_STRING, maxLength=12),
                'last_name': openapi.Schema(type=openapi.TYPE_STRING, maxLength=50),
                'profile_picture': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_BINARY),
                'password': openapi.Schema(type=openapi.TYPE_STRING, maxLength=50)
            },
            required=[]
        ),
        tags=['auth']

    )
    def profile_update(self, request, *args, **kwargs):
        if not (request.user.is_authenticated and request.user.is_verified):
            return Response({"detail": "User is not authenticated"}, status.HTTP_401_UNAUTHORIZED)
        user = request.user
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status.HTTP_200_OK)
        return Response(serializer.errors, status.HTTP_400_BAD_REQUEST)


