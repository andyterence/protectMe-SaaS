from django.urls import path

from .views import (
    AttackLogListView,
    AttackLogReviewView,
    ConnectionLogListView,
    DetectView,
    SimulateView,
)

urlpatterns = [
    path("detect", DetectView.as_view()),                              # /api/v1/detect - middleware uniquement
    path("attack-logs/", AttackLogListView.as_view()),                  # /api/v1/attack-logs/ - dashboard
    path("attack-logs/<int:pk>/review/", AttackLogReviewView.as_view()),
    path("connection-logs/", ConnectionLogListView.as_view()),
    path("simulate/", SimulateView.as_view()),
]
