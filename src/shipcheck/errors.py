"""Typed, user-safe Shipcheck errors."""


class ShipcheckError(Exception):
    """Base error with a stable machine-readable code."""

    code = "SHIPCHECK_ERROR"

    def __init__(self, message: str, *, detail: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail


class ValidationError(ShipcheckError):
    code = "INVALID_INPUT"


class SecurityError(ShipcheckError):
    code = "UNSAFE_INPUT"


class LedgerError(ShipcheckError):
    code = "LEDGER_ERROR"


class ConflictError(ShipcheckError):
    code = "IDEMPOTENCY_CONFLICT"


class NotFoundError(ShipcheckError):
    code = "NOT_FOUND"

