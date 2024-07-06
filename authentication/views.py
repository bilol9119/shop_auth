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
        tags=['user']

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
        manual_parameters=[openapi.Parameter(
            'Authorization',
            in_=openapi.IN_HEADER,
            description='Access token',
            type=openapi.TYPE_STRING,
            required=True
        )],
        responses={200: UserSerializer()},
        tags=['user']

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
        operation_summary="Update profile",
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
        tags=['user']

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


class RegisterAndVerifyViewSet(ViewSet):
    @swagger_auto_schema(
        operation_description="Register",
        operation_summary="Register new users",
        responses={201: OTPRegisterResendSerializer()},
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING, maxLength=12),
                'password': openapi.Schema(type=openapi.TYPE_STRING, maxLength=50),
            },
            required=['username', 'password']
        ),
        tags=['register']

    )
    def register(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')

        user = User.objects.filter(username=username).first()
        if user and user.is_verified:
            return Response(data={"error": "You already registered"}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_user_serializer(user, username, password)

        if serializer.is_valid():
            serializer.save()
        else:
            return Response({"error": serializer.errors}, status.HTTP_400_BAD_REQUEST)

        otp_check_result = self.handle_otp(serializer.instance)
        if otp_check_result:
            return otp_check_result

        return Response(data={"error": "Unknown error occurred"}, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_description="Register",
        operation_summary="Verify registered user",
        responses={200: "success"},
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'otp_key': openapi.Schema(type=openapi.TYPE_STRING, maxLength=50),
                'otp_code': openapi.Schema(type=openapi.TYPE_INTEGER),
            },
            required=['otp_key', 'otp_code']
        ),
        tags=['register']

    )
    def verify_register(self, request, *args, **kwargs):
        otp_key = request.data.get('otp_key')
        otp_code = request.data.get('otp_code')

        if not otp_code:
            return Response({"error": "Send otp code"}, status.HTTP_400_BAD_REQUEST)

        otp_obj = OTPRegisterResend.active_objects.filter(otp_key=otp_key).first()
        if otp_obj is None:
            return Response({"error": "Make sure otp key is right"}, status.HTTP_400_BAD_REQUEST)
        if otp_obj.otp_attempt > 3:
            return Response({"error": "Come back 12 hours later"}, status.HTTP_400_BAD_REQUEST)
        if otp_obj.otp_code != otp_code:
            otp_obj.otp_attempt += 1
            otp_obj.save(update_fields=['attempts'])
            return Response(data={"error": "otp code is wrong"}, status=status.HTTP_400_BAD_REQUEST)

        if not check_code_expire(otp_obj.created_at):
            return Response(data={"error": "Code is expired"}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(id=otp_obj.otp_user.id).first()
        if not user:
            return Response(data={"error": "User does not exist"}, status=status.HTTP_404_NOT_FOUND)

        user.is_verified = True
        user.save(update_fields=['is_verified'])

        self.delete_otps(user)

        return Response({"detail": "Success"}, status=status.HTTP_200_OK)

    def get_user_serializer(self, user, username, password):
        if user:
            return UserSerializer(user, data={'password': make_password(password)}, partial=True)
        else:
            return UserSerializer(data={"username": username, "password": make_password(password)})

    def handle_otp(self, user_instance):
        objs = OTPRegisterResend.active_objects.filter(
            otp_user=user_instance
        ).order_by('-created_at')

        otp_status = checking_number_of_otp(objs)
        if otp_status == 'limit_exceeded':
            return Response(data={"error": "Try again 12 hours later"}, status=status.HTTP_400_BAD_REQUEST)
        elif otp_status == 'delete':
            self.delete_otps(user_instance)

        return self.create_and_send_otp(user_instance)

    def delete_otps(self, user_instance):
        OTPRegisterResend.active_objects.filter(
            otp_user=user_instance
        ).update(deleted_at=datetime.now())

    def create_and_send_otp(self, user_instance):
        otp = OTPRegisterResend.objects.create(otp_user=user_instance)
        response = send_otp_code_telegram(otp)
        if response.status_code != 200:
            otp.deleted_at = datetime.now()
            otp.save(update_fields=['deleted_at'])
            return Response({"error": "Error occurred while sending OTP code"}, status=status.HTTP_400_BAD_REQUEST)
        return Response(data={"otp_key": otp.otp_key}, status=status.HTTP_201_CREATED)


class ResendAndResetViewSet(ViewSet):
    @swagger_auto_schema(
        operation_description="New password",
        operation_summary="Use for forget password operation",
        responses={200: "otp key returns"},
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING, maxLength=12),
            },
            required=['username']
        ),
        tags=['reset_password']

    )
    def reset_password(self, request, *args, **kwargs):
        username = request.data.get('username')
        user = User.objects.filter(username=username).first()
        if not user:
            return Response({"error": "User not found with this number!!!"})
        otp_obj = OTPSetPassword.objects.create(otp_user=user)
        otp_obj.save()
        response = send_otp_code_telegram(otp_obj)
        if response.status_code != 200:
            otp_obj.deleted_at = datetime.now()
            otp_obj.save(update_fields=['deleted_at'])
            return Response({"error": "Error occured while sending otp"}, status.HTTP_400_BAD_REQUEST)
        return Response({"otp_key": otp_obj.otp_key}, status.HTTP_200_OK)

    @swagger_auto_schema(
        operation_description="New password",
        operation_summary="Verifying before setting new password",
        responses={200: "otp token returns"},
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'otp_key': openapi.Schema(type=openapi.TYPE_STRING, maxLength=50),
                'otp_code': openapi.Schema(type=openapi.TYPE_INTEGER),
            },
            required=['otp_key', 'otp_code']
        ),
        tags=['reset_password']

    )
    def verify_reset_password(self, request, *args, **kwargs):
        otp_key = request.data.get('otp_key')
        otp_code = request.data.get('otp_code')

        otp_obj = OTPSetPassword.active_objects.filter(otp_key=otp_key).first()
        if not otp_obj:
            return Response({"Error": "Otp key is wrong"}, status.HTTP_400_BAD_REQUEST)
        if otp_obj.attempts > 2:
            return Response({"error": "Try again 12 hours later"}, status.HTTP_400_BAD_REQUEST)
        if otp_obj.otp_code != otp_code:
            otp_obj.attempts += 1
            return Response({"error": "Otp code is wrong"}, status.HTTP_400_BAD_REQUEST)
        return Response({"detail": "Success", "token": otp_obj.otp_token}, status.HTTP_200_OK)

    @swagger_auto_schema(
        operation_description="New password",
        operation_summary="setting new password by verifying with otp token",
        responses={200: "success"},
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'otp_token': openapi.Schema(type=openapi.TYPE_STRING, maxLength=50),
            },
            required=['otp_token']
        ),
        tags=['reset_password']

    )
    def set_new_password(self, request, *args, **kwargs):
        token = request.data.get('otp_token')
        otp_obj = OTPSetPassword.active_objects.filter(otp_token=token).first()
        if not otp_obj:
            return Response({"error": "Otp token is wrong"}, status.HTTP_400_BAD_REQUEST)

        if not check_token_expire(otp_obj.created_at):
            return Response({"error": "Token is expired"}, status.HTTP_400_BAD_REQUEST)

        password = request.data.get('password')
        rep_password = request.data.get('rep_password')

        if password != rep_password:
            return Response({"error": "Passwords are different!"}, status.HTTP_400_BAD_REQUEST)
        user = User.objects.filter(id=otp_obj.otp_user.id).first()
        if not user:
            return Response({"error": "User not found"}, status.HTTP_400_BAD_REQUEST)
        serializer = UserSerializer(user, data={'password': make_password(password)}, partial=True)
        if serializer.is_valid():
            serializer.save()
            otp_obj.deleted_at = datetime.now()
            otp_obj.save(update_fields=['deleted_at'])
            return Response(data={"detail": "success"}, status=status.HTTP_200_OK)
        return Response({"error": "Please enter a valid password"}, status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_description="Resend",
        operation_summary="Resend otp code ",
        responses={200: OTPRegisterResendSerializer()},
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'otp_key': openapi.Schema(type=openapi.TYPE_STRING, maxLength=50),
            },
            required=['otp_key']
        ),
        tags=['register']

    )
    def resend_otp_code(self, request, *args, **kwargs):
        otp_key = request.data.get('otp_key')
        otp_obj = OTPRegisterResend.active_objects.filter(otp_key=otp_key).first()
        if not otp_obj:
            return Response(data={"error": "Otp key is wrong"}, status=status.HTTP_400_BAD_REQUEST)

        objs = OTPRegisterResend.active_objects.filter(otp_user=otp_obj.otp_user).order_by(
            '-created_at')

        otp_status = checking_number_of_otp(objs)
        if otp_status == 'limit_exceeded':
            return Response(data={"error": "Try again 12 hours later"}, status=status.HTTP_400_BAD_REQUEST)
        elif otp_status == 'delete':
            OTPRegisterResend.active_objects.filter(
                otp_user=otp_obj.otp_user
            ).update(deleted_at=datetime.now())

        if not check_resend_otp_code(otp_obj.created_at):
            return Response(data={"error": "Try again a minute later"}, status=status.HTTP_400_BAD_REQUEST)

        new_otp = OTPRegisterResend.objects.create(otp_user=otp_obj.otp_user, otp_type=2)
        new_otp.save()
        response = send_otp_code_telegram(new_otp)
        if response.status_code != 200:
            new_otp.deleted_at = datetime.now()
            new_otp.save(update_fields=['deleted_at'])
            return Response({"error": "Could not send otp to telegram"}, status.HTTP_400_BAD_REQUEST)
        otp_obj.deleted_at = datetime.now()
        otp_obj.save(update_fields=['deleted_at'])
        return Response(data={"otp_key": new_otp.otp_key}, status=status.HTTP_200_OK)
