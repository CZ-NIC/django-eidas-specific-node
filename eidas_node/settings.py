"""Settings helpers."""

from enum import Enum
from typing import Generic, TypeVar

from appsettings import Setting
from django.core.exceptions import ValidationError

T = TypeVar("T", bound=Enum)


class EnumSetting(Setting, Generic[T]):
    """Enumeration setting."""

    def __init__(self, enum_type: type[T], *args, **kwargs):
        kwargs.setdefault("transform_default", True)
        super().__init__(*args, **kwargs)
        self.enum_type = enum_type

    def validate(self, value) -> None:
        """Validate an enumeration value."""
        try:
            self.transform(value)
        except KeyError:
            raise ValidationError(
                "{!r} is not a valid {}. Available values: {!r}".format(
                    value, self.enum_type.__name__, {m.name for m in self.enum_type}
                )
            )

    def transform(self, value) -> T:
        """Transform member name to the corresponding enumeration value."""
        return self.enum_type[value]
