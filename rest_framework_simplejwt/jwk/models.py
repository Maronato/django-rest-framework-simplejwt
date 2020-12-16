import json
from typing import Optional, Tuple, Type, Dict, cast
from datetime import datetime
from uuid import uuid4, UUID
from django.utils.translation import gettext_lazy as _
from django.db import models
from django.dispatch import receiver
from django.conf import settings
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from jwt import algorithms

from ..exceptions import TokenBackendError
from ..utils import format_lazy, aware_utcnow, datetime_to_epoch
from ..settings import api_settings


class JWK(models.Model):
    created_at: datetime = models.DateTimeField(_("Created at"))
    expires_at: datetime = models.DateTimeField(_("Expires at"))

    KEY_ALGORITHM_RS256 = "RS256"
    KEY_ALGORITHM_RS384 = "RS384"
    KEY_ALGORITHM_RS512 = "RS512"
    RSA_ALGORITHMS = (KEY_ALGORITHM_RS256, KEY_ALGORITHM_RS384, KEY_ALGORITHM_RS512)
    KEY_ALGORITHMS = (
        (KEY_ALGORITHM_RS256, "RS256"),
        (KEY_ALGORITHM_RS384, "RS384"),
        (KEY_ALGORITHM_RS512, "RS512"),
    )
    algorithm: str = models.CharField(
        _("Algorithm"),
        max_length=10,
        choices=KEY_ALGORITHMS,
        blank=True,
        default=KEY_ALGORITHM_RS512,
    )
    _private_key: bytes = models.BinaryField(_("Private key"), null=True, default=None)

    public_exponent: int = models.IntegerField(_("Public exponent"), default=65537)

    KEY_SIZE_1024 = 1024
    KEY_SIZE_2048 = 2048
    KEY_SIZE_4096 = 4096
    KEY_SIZES = (
        (KEY_SIZE_1024, "1024"),
        (KEY_SIZE_2048, "2048"),
        (KEY_SIZE_4096, "4096"),
    )
    key_size: int = models.IntegerField(
        _("Key size"), default=KEY_SIZE_2048, choices=KEY_SIZES
    )

    key_id: UUID = models.UUIDField(_("Key ID"), editable=False, default=uuid4)

    KEY_TYPE_RSA = "RSA"

    @property
    def key_type(self):
        return self.KEY_TYPE_RSA if self.algorithm in self.RSA_ALGORITHMS else None

    @property
    def kid(self) -> str:
        return str(self.key_id)

    def get_password(self) -> bytes:
        return settings.SECRET_KEY.encode()

    def generate_private_key(self):
        if self.key_type == self.KEY_TYPE_RSA:
            key = rsa.generate_private_key(
                public_exponent=self.public_exponent, key_size=self.key_size
            )
        else:
            raise TokenBackendError(
                format_lazy(_("Unrecognized algorithm type '{}'"), self.algorithm)
            )

        self._private_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                password=self.get_password()
            ),
        )
        self.save()
        return self

    def to_jwk(self) -> Dict[str, str]:
        if self.key_type == self.KEY_TYPE_RSA:
            jwk = json.loads(algorithms.RSAAlgorithm.to_jwk(self.public_key))
            jwk["alg"] = self.algorithm
            jwk["kid"] = self.kid
            jwk["exp"] = datetime_to_epoch(self.expires_at)
        else:
            raise TokenBackendError(
                format_lazy(_("Unrecognized algorithm type '{}'"), self.algorithm)
            )
        return jwk

    @property
    def private_key(self) -> rsa.RSAPrivateKeyWithSerialization:
        if self.key_type == self.KEY_TYPE_RSA:
            return serialization.load_pem_private_key(
                data=self._private_key, password=self.get_password()
            )
        else:
            raise TokenBackendError(
                format_lazy(_("Unrecognized algorithm type '{}'"), self.algorithm)
            )

    @property
    def private_key_PEM(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @property
    def public_key(self) -> rsa.RSAPublicKeyWithSerialization:
        return self.private_key.public_key()

    @property
    def public_key_PEM(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @property
    def is_expired(self) -> bool:
        return (
            aware_utcnow()
            > self.created_at
            + api_settings.JWK_LIFETIME
            + api_settings.REFRESH_TOKEN_LIFETIME
        )

    @property
    def is_rotated(self) -> bool:
        return aware_utcnow() > self.created_at + api_settings.JWK_LIFETIME

    @classmethod
    def get_current_jwk(cls) -> "JWK":
        """Current key pair in PEM format

        Returns:
            Tuple[bytes, bytes]: Tuple (private_key, public_key)
        """
        current = cast(Optional["JWK"], cls.objects.first())
        if current is None or current.is_rotated:
            current = cls.rotate_keys()

        return current

    @classmethod
    def rotate_keys(cls) -> "JWK":
        current_time = aware_utcnow()
        instance: JWK = cls(
            algorithm=api_settings.ALGORITHM,
            key_size=api_settings.KEY_SIZE,
            public_exponent=api_settings.PUBLIC_EXPONENT,
            created_at=current_time,
            expires_at=current_time
            + api_settings.JWK_LIFETIME
            + api_settings.REFRESH_TOKEN_LIFETIME,
        )
        return instance.generate_private_key()

    def __str__(self):
        return f"JWK #{self.key_id} ({self.algorithm})"

    class Meta:
        ordering = ["-created_at"]
        verbose_name = _("JWK")
        verbose_name_plural = _("JWKs")
        # Work around for a bug in Django:
        # https://code.djangoproject.com/ticket/19422
        #
        # Also see corresponding ticket:
        # https://github.com/encode/django-rest-framework/issues/705
        abstract = "rest_framework_simplejwt.jwk" not in settings.INSTALLED_APPS


@receiver(models.signals.pre_save, sender=JWK)
def generate_jwk_keys(sender: Type[JWK], instance: JWK, **kwargs):
    # If being created
    if instance.id is None and instance.private_key is None:
        instance.generate_private_key()
