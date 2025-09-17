"""Settings of eidas_node.connector."""

from appsettings import (
    AppSettings,
    BooleanSetting,
    DictSetting,
    IterableSetting,
    ListSetting,
    NestedDictSetting,
    PositiveIntegerSetting,
    StringSetting,
)
from django.core.exceptions import ImproperlyConfigured

from eidas_node.attributes import ATTRIBUTE_MAP
from eidas_node.constants import XmlBlockCipher, XmlKeyTransport
from eidas_node.settings import EnumSetting

DEFAULT_COUNTRIES = [
    # Country code, name
    ("AT", "Austria"),
    ("BE", "Belgium"),
    ("BG", "Bulgaria"),
    ("CY", "Republic of Cyprus"),
    ("CZ", "Czech Republic"),
    ("DE", "Germany"),
    ("DK", "Denmark"),
    ("EE", "Estonia"),
    ("ES", "Spain"),
    ("FI", "Finland"),
    ("FR", "France"),
    ("GB", "Great Britain"),
    ("GR", "Greece"),
    ("HR", "Croatia"),
    ("HU", "Hungary"),
    ("IE", "Republic of Ireland"),
    ("IS", "Iceland"),
    ("IT", "Italy"),
    ("LI", "Liechtenstein"),
    ("LT", "Lithuania"),
    ("LU", "Luxembourg"),
    ("LV", "Latvia"),
    ("MT", "Malta"),
    ("NL", "Netherlands"),
    ("NO", "Norway"),
    ("PL", "Poland"),
    ("PT", "Portugal"),
    ("RO", "Romania"),
    ("SE", "Sweden"),
    ("SI", "Slovenia"),
    ("SK", "Slovakia"),
]


class ConnectorSettings(AppSettings):
    """eIDAS Node Connector settings."""

    request_token = NestedDictSetting(
        settings={
            "hash_algorithm": StringSetting(default="sha256", min_length=1),
            "parameter_name": StringSetting(default="token", min_length=1),
            "secret": StringSetting(required=True, min_length=1),
            "issuer": StringSetting(required=True, min_length=1),
        },
        required=True,
    )
    response_token = NestedDictSetting(
        settings={
            "hash_algorithm": StringSetting(default="sha256", min_length=1),
            "parameter_name": StringSetting(default="token", min_length=1),
            "secret": StringSetting(required=True, min_length=1),
            "issuer": StringSetting(required=True, min_length=1),
            "lifetime": PositiveIntegerSetting(default=10),
        },
        required=True,
    )
    service_provider = NestedDictSetting(
        settings={
            "endpoint": StringSetting(required=True, min_length=1),
            "cert_files": ListSetting(item_type=str),
            "request_issuer": StringSetting(required=True, min_length=1),
            "response_issuer": StringSetting(required=True, min_length=1),
            "response_signature": NestedDictSetting(
                settings={
                    # required=True leads to a strange error:
                    # "RESPONSE_SIGNATURE setting is missing required item 'RESPONSE_SIGNATURE'"
                    "key_source": StringSetting(min_length=1),
                    "key_location": StringSetting(min_length=1),
                    "cert_file": StringSetting(min_length=1),
                    "signature_method": StringSetting(default="RSA_SHA512", min_length=1),
                    "digest_method": StringSetting(default="SHA512", min_length=1),
                },
                # https://github.com/pawamoy/django-appsettings/issues/91
                required=True,
            ),
            "response_encryption": NestedDictSetting(
                settings={
                    # required=True leads to a strange error as in response_signature above.
                    "cert_file": StringSetting(min_length=1),
                    "encryption_method": EnumSetting(XmlBlockCipher, default="AES256_GCM"),
                    "key_transport": EnumSetting(XmlKeyTransport, default="RSA_OAEP_MGF1P"),
                },
                # https://github.com/pawamoy/django-appsettings/issues/91
                required=True,
            ),
            "response_validity": PositiveIntegerSetting(default=10),
            "country_parameter": StringSetting(default="country", min_length=1),
        },
        required=True,
    )
    light_storage = NestedDictSetting(
        settings={
            "backend": StringSetting(default="eidas_node.storage.ignite.IgniteStorage", min_length=1),
            "options": DictSetting(required=True),
        },
        required=True,
    )
    eidas_node = NestedDictSetting(
        settings={
            "connector_request_url": StringSetting(required=True, min_length=1),
            "request_issuer": StringSetting(required=True, min_length=1),
        },
        required=True,
    )
    allowed_attributes = IterableSetting(default=set(ATTRIBUTE_MAP))
    selector_countries = IterableSetting(default=DEFAULT_COUNTRIES, min_length=1)
    track_country_code = BooleanSetting(default=False)
    auxiliary_storage = NestedDictSetting(
        settings={
            "backend": StringSetting(default="eidas_node.storage.ignite.AuxiliaryIgniteStorage", min_length=1),
            "options": DictSetting(required=True),
        }
    )

    class Meta:
        """Metadata."""

        setting_prefix = "connector_"


CONNECTOR_SETTINGS = ConnectorSettings()


def check_settings():
    """Check settings."""
    ConnectorSettings.check()
    signature = CONNECTOR_SETTINGS.service_provider["response_signature"]
    # If one of the files is set, the other must be set as well
    if not (
        bool(signature.get("key_source")) == bool(signature.get("key_location")) == bool(signature.get("cert_file"))
    ):
        raise ImproperlyConfigured(
            "CONNECTOR_SERVICE_PROVIDER.RESPONSE_SIGNATURE.KEY_SOURCE, "
            "CONNECTOR_SERVICE_PROVIDER.RESPONSE_SIGNATURE.KEY_LOCATION and "
            "CONNECTOR_SERVICE_PROVIDER.RESPONSE_SIGNATURE.CERT_FILE must be set."
        )

    auxiliary_required = CONNECTOR_SETTINGS.track_country_code
    if auxiliary_required and not CONNECTOR_SETTINGS.auxiliary_storage:
        raise ImproperlyConfigured(
            "CONNECTOR_AUXILIARY_STORAGE is required if CONNECTOR_TRACK_COUNTRY_CODE is enabled."
        )
