from django.urls import path

from .views import TicketAdminUpdateView, TicketListCreateView

urlpatterns = [
    path("", TicketListCreateView.as_view()),
    path("<int:pk>/", TicketAdminUpdateView.as_view()),
]
