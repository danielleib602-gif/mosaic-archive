"""Private ABI3 binding contract for the authenticated M7A0 preview."""

BINDING_API_VERSION: int

class AuthenticationError(Exception): ...
class FormatError(Exception): ...
class OptionsError(Exception): ...
class CodecError(Exception): ...

def encode_file(
    input: str,
    output: str,
    password: bytes,
    *,
    threads: int = 1,
    kdf_log_n: int = 17,
    max_input_bytes: int = 8_589_934_592,
) -> dict[str, object]: ...

def decode_file(
    input: str,
    output: str,
    password: bytes,
    *,
    max_output_bytes: int = 8_589_934_592,
    max_encoded_bytes: int = 8_606_711_808,
    max_segments: int = 131_072,
    max_records: int = 2_000_000,
    max_expansion_ratio: int = 16_384,
    max_archive_bytes: int = 8_673_820_672,
    max_data_records: int = 1_000_000,
    max_kdf_log_n: int = 17,
) -> dict[str, object]: ...

def inspect_file(
    input: str,
    password: bytes,
    *,
    max_output_bytes: int = 8_589_934_592,
    max_encoded_bytes: int = 8_606_711_808,
    max_segments: int = 131_072,
    max_records: int = 2_000_000,
    max_expansion_ratio: int = 16_384,
    max_archive_bytes: int = 8_673_820_672,
    max_data_records: int = 1_000_000,
    max_kdf_log_n: int = 17,
) -> dict[str, object]: ...
