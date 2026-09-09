from django.urls import path

from .views import (
    ChangePasswordView, DeleteAccountView, LoginView, LogoutView, MeView, RefreshView, RegisterView, UserListView, UserToggleActiveView 
)

urlpatterns = [
    path("login/", LoginView.as_view()),
    path("register/", RegisterView.as_view()),
    path("refresh/", RefreshView.as_view()),
    path("logout/", LogoutView.as_view()),
    path("me/", MeView.as_view()),
    path("change-password/", ChangePasswordView.as_view()),
    path("delete-account/", DeleteAccountView.as_view()),
    path("users/", UserListView.as_view()),
    path("users/<int:pk>/toggle-active/", UserToggleActiveView.as_view()),
]