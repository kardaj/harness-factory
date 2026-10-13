"""An opaque resolved secret that must be revealed explicitly."""

from __future__ import annotations

import hmac
from typing import NoReturn


class SecretValue:
    """A resolved secret whose printed and formatted forms are redacted.

    ``str``, ``repr``, and format strings show ``<redacted>``; JSON encoding and
    pickling fail. Consumers that must write the value call ``reveal()``. This
    prevents accidental disclosure only: Python callers can always reveal the
    value, and its memory is not erased.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("secret values must be strings")
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "<redacted>"

    __str__ = __repr__

    def __format__(self, spec: str) -> str:
        return "<redacted>"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecretValue):
            return NotImplemented
        return hmac.compare_digest(self._value.encode(), other._value.encode())

    def __hash__(self) -> int:
        return hash((SecretValue, self._value))

    def __reduce__(self) -> NoReturn:
        raise TypeError("secret values cannot be pickled")
