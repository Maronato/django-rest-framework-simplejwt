from django.db.models.query import QuerySet
from django.utils.http import http_date
from rest_framework import permissions, views, request, response, renderers
from .models import JWK
from ..utils import datetime_to_epoch


class JWKList(views.APIView):
    permission_classes = [permissions.AllowAny]
    renderer_classes = [renderers.JSONRenderer]

    def get(self, request: request.Request):
        current_jwk = JWK.get_current_jwk()
        jwks: QuerySet[JWK] = JWK.objects.all()
        keys = list(map(lambda k: k.to_jwk(), jwks))
        return response.Response(
            {"keys": keys},
            content_type="application/json",
            headers={"Expires": http_date(datetime_to_epoch(current_jwk.expires_at))},
        )
