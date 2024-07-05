import random
import requests
import re
from datetime import datetime, timedelta
from django.core.exceptions import ValidationError
from config.settings import TELEGRAM_API_URL, BOT_ID, CHAT_ID

number_codes = ('99', '98', '97', '95', '94', '93', '91', '90', '77', '55', '33', '71')


def send_otp_code_telegram(otp_obj):
    message = (f"Project: SHOP\n PhoneNumber: {otp_obj.otp_user.username}\n "
               f"code: {otp_obj.otp_code}\n key: {otp_obj.otp_key}\n "
               f"sender: UzMOVIE")
    response = requests.get(TELEGRAM_API_URL.format(BOT_ID, message, CHAT_ID))
    return response


def generate_otp_code():
    return random.randint(10000, 99999)


def check_code_expire(created_at):
    current_time = datetime.now()
    if current_time - created_at > timedelta(minutes=3):
        return False
    return True


def username_validation(username):
    pattern = r'^998(' + '|'.join(number_codes) + r')\d{7}$'
    if re.match(pattern, username):
        return True
    raise ValidationError('Username should be an Uzbek phone number')


def checking_number_of_otp(checking_otp_objs):
    if len(checking_otp_objs) < 3:
        return True

    current_time = datetime.now()
    oldest_otp = checking_otp_objs[0]

    if current_time - oldest_otp.created_at < timedelta(hours=12):
        return 'limit_exceeded'

    return 'delete'


def check_resend_otp_code(created_at):
    current_time = datetime.now()
    if current_time - created_at < timedelta(minutes=1):
        return False
    return True


def check_token_expire(created_at):
    current_time = datetime.now()
    if current_time - created_at < timedelta(minutes=30):
        return False
    return True
