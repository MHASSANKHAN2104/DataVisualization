from django.shortcuts import get_object_or_404
from django.utils import timezone

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions

from .models import User, RefreshToken, AuditLog
from .serializers import (
    SignupSerializer,
    LoginSerializer,
    UserSerializer,
    UserUpdateSerializer,
)
from .tokens import issue_token_pair
import jwt
from django.conf import settings


# ----- Helper: audit logging -----

def audit(actor, action, target_type, target_id, metadata=None):
    AuditLog.objects.create(
        actor_user=actor,
        action=action,
        target_type=target_type,
        target_id=str(target_id),
        metadata=metadata or {},
    )


# ----- Auth views -----

class SignupView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({"user_id": user.id}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data,
                                     context={'request': request})
        if not serializer.is_valid():
            # (Optional: increment failed_login_attempts here)
            return Response({"detail": "Invalid email or password."},
                            status=status.HTTP_401_UNAUTHORIZED)

        user = serializer.validated_data['user']

        # Reset failed attempts & update last_login_at
        user.failed_login_attempts = 0
        user.last_login_at = timezone.now()
        user.save(update_fields=['failed_login_attempts', 'last_login_at'])

        tokens = issue_token_pair(user, request)
        return Response(tokens, status=status.HTTP_200_OK)


class RefreshView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        refresh_token_str = request.data.get('refresh')
        if not refresh_token_str:
            return Response({"detail": "Refresh token required."},
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            payload = jwt.decode(
                refresh_token_str,
                settings.SECRET_KEY,
                algorithms=['HS256'],
            )
        except jwt.ExpiredSignatureError:
            return Response({"detail": "Token has expired."},
                            status=status.HTTP_401_UNAUTHORIZED)
        except jwt.PyJWTError:
            return Response({"detail": "Invalid token."},
                            status=status.HTTP_401_UNAUTHORIZED)

        if payload.get('type') != 'refresh':
            return Response({"detail": "Invalid token type."},
                            status=status.HTTP_401_UNAUTHORIZED)

        jti = payload.get('jti')

        try:
            db_token = RefreshToken.objects.select_related('user').get(jti=jti)
        except RefreshToken.DoesNotExist:
            return Response({"detail": "Token revoked."},
                            status=status.HTTP_401_UNAUTHORIZED)

        if not db_token.is_active:
            return Response({"detail": "Token revoked or expired."},
                            status=status.HTTP_401_UNAUTHORIZED)

        # rotate refresh token
        db_token.revoked_at = timezone.now()
        db_token.save(update_fields=['revoked_at'])

        new_tokens = issue_token_pair(db_token.user, request)
        return Response(new_tokens, status=status.HTTP_200_OK)


class LogoutView(APIView):
    """
    POST /auth/logout  { "refresh": "<refresh_token>" }
    Revokes that refresh token (jti).
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        refresh_token_str = request.data.get('refresh')
        if not refresh_token_str:
            return Response({"detail": "Refresh token required."},
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            payload = jwt.decode(
                refresh_token_str,
                settings.SECRET_KEY,
                algorithms=['HS256'],
            )
        except jwt.PyJWTError:
            # already invalid → treat as logged out
            return Response(status=status.HTTP_204_NO_CONTENT)

        if payload.get('type') != 'refresh':
            return Response(status=status.HTTP_204_NO_CONTENT)

        jti = payload.get('jti')
        try:
            db_token = RefreshToken.objects.get(jti=jti)
            db_token.revoked_at = timezone.now()
            db_token.save(update_fields=['revoked_at'])
        except RefreshToken.DoesNotExist:
            pass

        return Response(status=status.HTTP_204_NO_CONTENT)


# ----- Permissions -----

class IsAdminRole(permissions.BasePermission):
    def has_permission(self, request, view):
        return bool(
            request.user
            and request.user.is_authenticated
            and request.user.role == 'Admin'
        )


# ----- User/profile views -----

class MeView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)


class UserListView(APIView):
    """
    Admin-only list of users
    """
    permission_classes = [permissions.IsAuthenticated, IsAdminRole]

    def get(self, request):
        users = User.objects.all().order_by('id')
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)


class UserDetailView(APIView):
    """
    Admin PATCH /users/<id> to change role/status.
    """
    permission_classes = [permissions.IsAuthenticated, IsAdminRole]

    def patch(self, request, id):
        user = get_object_or_404(User, pk=id)
        old_role = user.role
        old_status = user.status

        serializer = UserUpdateSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()

            if user.role != old_role:
                audit(
                    actor=request.user,
                    action='user.role_changed',
                    target_type='user',
                    target_id=user.id,
                    metadata={'from': old_role, 'to': user.role},
                )

            if user.status != old_status:
                audit(
                    actor=request.user,
                    action='user.status_changed',
                    target_type='user',
                    target_id=user.id,
                    metadata={'from': old_status, 'to': user.status},
                )

            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
