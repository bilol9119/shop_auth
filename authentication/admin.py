from django.contrib import admin
from .models import User, OTPSetPassword, OTPRegisterResend

admin.site.register(User)
admin.site.register(OTPSetPassword)
admin.site.register(OTPRegisterResend)
