from django.urls import path
from .views import (
    SignupView,
    LoginView,
    RefreshView,
    LogoutView,
    MeView,
    UserListView,
    UserDetailView,
)

urlpatterns = [
    path('auth/signup', SignupView.as_view(), name='auth-signup'),
    path('auth/login', LoginView.as_view(), name='auth-login'),
    path('auth/refresh', RefreshView.as_view(), name='auth-refresh'),
    path('auth/logout', LogoutView.as_view(), name='auth-logout'),
    path('me', MeView.as_view(), name='me'),
    path('users', UserListView.as_view(), name='user-list'),
    path('users/<int:id>', UserDetailView.as_view(), name='user-detail'),
]
