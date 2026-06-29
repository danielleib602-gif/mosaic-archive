"""Domain exceptions with safe, user-facing messages."""


class MosaicError(Exception):
    """Base exception for expected Mosaic Archive failures."""


class ArchiveFormatError(MosaicError):
    """The input does not conform to the supported MSC format."""


class UnsupportedVersionError(ArchiveFormatError):
    """The archive uses a version this implementation cannot decode."""


class AuthenticationError(MosaicError):
    """Password verification or AEAD authentication failed."""


class IntegrityError(MosaicError):
    """Authenticated archive contents did not reproduce the stored digest."""

