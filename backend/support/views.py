from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from .models import SupportTicket
from .serializers import SupportTicketAdminUpdateSerializer, SupportTicketSerializer


class TicketListCreateView(APIView):
    """Un User ne voit que SES tickets ; l'Admin (Developpeur du Modele)
    voit et traite tous les tickets, coherent avec le tableau de
    permissions du cahier des charges ("Gerer les utilisateurs" = Admin).
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = SupportTicket.objects.all() if request.user.role == "admin" else SupportTicket.objects.filter(created_by=request.user)
        return Response(SupportTicketSerializer(qs, many=True).data)

    def post(self, request):
        serializer = SupportTicketSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        ticket = serializer.save(created_by=request.user)
        return Response(SupportTicketSerializer(ticket).data, status=201)


class TicketAdminUpdateView(APIView):
    """PATCH reservee a l'Admin : repondre et/ou changer le statut."""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        if request.user.role != "admin":
            raise PermissionDenied("Reserve a l'Admin.")

        try:
            ticket = SupportTicket.objects.get(pk=pk)
        except SupportTicket.DoesNotExist:
            raise NotFound("Ticket introuvable.")

        serializer = SupportTicketAdminUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        for field, value in serializer.validated_data.items():
            setattr(ticket, field, value)
        ticket.save()
        return Response(SupportTicketSerializer(ticket).data)
