from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.utils import timezone
import uuid


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Users must have an email address")
        email = self.normalize_email(email)

        extra_fields.setdefault('role', 'Viewer')
        extra_fields.setdefault('status', 'Active')

        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('role', 'Admin')
        extra_fields.setdefault('status', 'Active')
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = [
        ('Admin', 'Admin'),
        ('Owner', 'Owner'),
        ('Analyst', 'Analyst'),
        ('Viewer', 'Viewer'),
    ]
    STATUS_CHOICES = [
        ('Active', 'Active'),
        ('Disabled', 'Disabled'),
        ('Locked', 'Locked'),
    ]

    email = models.EmailField(unique=True)
    name = models.CharField(max_length=255, blank=True)

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='Viewer')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Active')

    failed_login_attempts = models.IntegerField(default=0)
    lock_until = models.DateTimeField(null=True, blank=True)

    last_login_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Django flags
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email

    def is_locked(self):
        return self.status == 'Locked' and (
            self.lock_until is None or self.lock_until > timezone.now()
        )


class RefreshToken(models.Model):
    """
    Stores refresh token jti so we can revoke/rotate.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='refresh_tokens')
    jti = models.UUIDField(default=uuid.uuid4, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    replaced_by = models.OneToOneField(
        'self',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='replaces'
    )
    user_agent = models.CharField(max_length=255, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    @property
    def is_active(self):
        return self.revoked_at is None and self.expires_at > timezone.now()


class AuditLog(models.Model):
    """
    Records who did what (role changes, deletes, etc.).
    """
    actor_user = models.ForeignKey(User, null=True, blank=True,
                                   on_delete=models.SET_NULL)
    action = models.CharField(max_length=120)
    target_type = models.CharField(max_length=50)   # 'user', 'dataset', ...
    target_id = models.CharField(max_length=50)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.action} on {self.target_type}:{self.target_id}'
