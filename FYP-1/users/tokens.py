import jwt
import uuid
from datetime import datetime, timedelta, timezone
from django.conf import settings
from .models import RefreshToken

ACCESS_LIFETIME_MIN = 15          # adjust if needed
REFRESH_LIFETIME_DAYS = 7


def _build_payload(user, jti, token_type, expires_delta):
    now = datetime.now(timezone.utc)
    return {
        'sub': str(user.id),
        'email': user.email,
        'role': user.role,
        'type': token_type,
        'jti': str(jti),
        'iat': int(now.timestamp()),
        'exp': int((now + expires_delta).timestamp()),
    }


def issue_token_pair(user, request=None):
    # create refresh record first
    refresh_obj = RefreshToken.objects.create(
        user=user,
        expires_at=datetime.now(timezone.utc) + timedelta(days=REFRESH_LIFETIME_DAYS),
        user_agent=request.META.get('HTTP_USER_AGENT', '') if request else '',
        ip_address=request.META.get('REMOTE_ADDR') if request else None,
    )

    access_payload = _build_payload(
        user,
        jti=uuid.uuid4(),
        token_type='access',
        expires_delta=timedelta(minutes=ACCESS_LIFETIME_MIN),
    )
    refresh_payload = _build_payload(
        user,
        jti=refresh_obj.jti,
        token_type='refresh',
        expires_delta=timedelta(days=REFRESH_LIFETIME_DAYS),
    )

    access_token = jwt.encode(access_payload, settings.SECRET_KEY, algorithm='HS256')
    refresh_token = jwt.encode(refresh_payload, settings.SECRET_KEY, algorithm='HS256')

    return {
        'access': access_token,
        'refresh': refresh_token,
        'expires_in': ACCESS_LIFETIME_MIN * 60,  # seconds
    }
