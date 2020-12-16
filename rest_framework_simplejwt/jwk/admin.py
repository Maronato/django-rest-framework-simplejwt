from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from .models import JWK


@admin.register(JWK)
class JWKAdmin(admin.ModelAdmin):
    list_display = (
        "algorithm",
        "key_id",
        "expires_at",
        "created_at",
    )
    search_fields = (
        "key_id",
        "algorithm",
    )

    def get_readonly_fields(self, *args, **kwargs):
        return [f.name for f in self.model._meta.fields]
