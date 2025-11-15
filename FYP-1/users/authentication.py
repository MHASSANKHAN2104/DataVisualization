from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions
from django.contrib.auth import get_user_model
from django.conf import settings
import jwt

User = get_user_model()


class JWTAuthentication(BaseAuthentication):
    """
    Reads Authorization: Bearer <access_token> and sets request.user
    """
    keyword = 'Bearer'

    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if not auth_header.startswith(self.keyword + ' '):
            return None

        token = auth_header.split(' ', 1)[1]

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed('Token has expired.')
        except jwt.PyJWTError:
            raise exceptions.AuthenticationFailed('Invalid token.')

        if payload.get('type') != 'access':
            raise exceptions.AuthenticationFailed('Invalid token type.')

        user_id = payload.get('sub')
        try:
            user = User.objects.get(id=user_id, status='Active')
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed('User not found or inactive.')

        request.jwt_payload = payload
        return (user, None)
