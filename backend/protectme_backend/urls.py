from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/auth/", include("accounts.urls")),
    path("api/sites/", include("sites.urls")),
    path("api/tickets/", include("support.urls")),
    path("api/v1/", include("detection.urls")),  # -> /api/v1/detect, /api/v1/attack-logs/, ...
]
