from rest_framework.serializers import ModelSerializer, Serializer
from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from .models import User, OTPRegisterResend, OTPSetPassword
from .utils import username_validation


class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'profile_picture', 'password')
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def update(self, instance, validated_data):
        instance.password = make_password(validated_data.get('password', instance.password))
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.profile_picture = validated_data.get('profile_picture', instance.profile_picture)
        instance.save()
        return instance


class OTPRegisterResendSerializer(ModelSerializer):
    class Meta:
        model = OTPRegisterResend
        fields = ('otp_key',)


class OTPSetPasswordSerializer(ModelSerializer):
    class Meta:
        model = OTPSetPassword
        fields = ('otp_key',)
