from django.db.models.query import QuerySet
from rest_framework import permissions, views, request, response
from .models import JWK


class JWKList(views.APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request: request.Request):
        jwks: QuerySet[JWK] = JWK.objects.all()
        keys = list(map(lambda k: k.to_jwk(), jwks))
        return response.Response({"keys": keys}, content_type="application/json")
