from django.urls import path
from .views import SiteListCreateView, SiteDetailView, SiteRegenerateKeyView

urlpatterns = [
    path("", SiteListCreateView.as_view()),
    path("<int:pk>/", SiteDetailView.as_view()),
    path("<int:pk>/regenerate-key/", SiteRegenerateKeyView.as_view()),
]