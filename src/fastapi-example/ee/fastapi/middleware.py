import base64
import traceback
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from typing import Callable
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import Request, Response
from fastapi.routing import APIRoute


class SegmentType(Enum):
    PLAIN = 1
    ENCRYPTED = 2
    SHARED_KEY = 3


class SegmentURLType(Enum):
    NONE = 0
    PATH = 1
    QUERY = 2


@dataclass
class Segment:
    value: str
    segment_type: SegmentType
    segment_url_type: SegmentURLType = SegmentURLType.NONE


# TODO Feature: return segments with URL type (for better post decrypt filtering)
# TODO Feature: token mode: use a unique token per user (statefull)
# TODO Feature: mac mode: use a mac for every ULR without encryption
class EncryptedURL:
    """EncryptedURL. A class to handle encrypted URLs. Provides methods to decrypt and encrypt URLs."""

    SHARED_KEY_TYPE = "!"

    def __init__(self, path_and_query: str, DELIMITER: str = "~") -> None:
        """
        Initializes an object to parse and store segments of a URL, distinguishing between encrypted
        and cleartext parts using a specified delimiter. This is particularly useful for URLs containing
        dynamic parts that cannot be encrypted server-side. The segments are stored in an encrypted form and
        require decryption through a separate call to access their cleartext values.

        Args:
            path_and_query (str): The URL's path and query string to be parsed. This should include both the
                path and the query component of the URL, if present.
            DELIMITER (str, optional): The delimiter used to separate encrypted parts from cleartext parts within
                the URL. This is crucial for URLs with dynamic parts that are not encrypted
                server-side. The default delimiter is "~".
        """
        self.DELIMITER = DELIMITER
        self.path_segments = self._parse_encrypted_url(path_and_query)

    def _parse_encrypted_url(self, path_and_query: str):
        if (
            path_and_query and path_and_query[0] == "/"
        ):  # / is appended by default but cannot be decrypted
            path_and_query = path_and_query[1:]

        segments = []
        index = 0
        while index < len(path_and_query):
            if path_and_query[index] == self.DELIMITER:
                next_delimiter = path_and_query.find(self.DELIMITER, index + 1)
                if next_delimiter != -1:
                    segments.append(
                        Segment(
                            path_and_query[index + 1 : next_delimiter],
                            SegmentType.ENCRYPTED,
                        )
                    )
                    index = next_delimiter + 1
                else:
                    break
            else:
                next_delimiter_or_end = path_and_query.find(self.DELIMITER, index)
                if next_delimiter_or_end != -1:
                    segments.append(
                        Segment(
                            path_and_query[index:next_delimiter_or_end],
                            SegmentType.PLAIN,
                        )
                    )
                    index = next_delimiter_or_end
                else:
                    segments.append(Segment(path_and_query[index:], SegmentType.PLAIN))
                    index = len(path_and_query)
        if segments and segments[-1].value.startswith(self.SHARED_KEY_TYPE):
            segments[-1].value = segments[-1].value[1:]
            segments[-1].segment_type = SegmentType.SHARED_KEY

        return segments

    def get_full_url(self, shared_segment=True) -> str:
        """Get the full URL from the stored segments. Non-mutable operation.

        Args:
            shared_segment (bool, optional): Whether to include the shared version or not.

        Returns:
            str: The full URL
        """
        url = ""
        for segment in self.path_segments:
            if segment.segment_type == SegmentType.ENCRYPTED:
                url += f"{self.DELIMITER}{segment.value}{self.DELIMITER}"
            elif segment.segment_type == SegmentType.PLAIN:
                url += segment.value
            elif segment.segment_type == SegmentType.SHARED_KEY and shared_segment:
                url += f"{self.DELIMITER}{self.SHARED_KEY_TYPE}{segment.value}{self.DELIMITER}"
        return url

    def is_shared_url(self):
        return (
            self.path_segments
            and self.path_segments[-1].segment_type == SegmentType.SHARED_KEY
        )

    def decrypt_url(self, main_key: bytes, identifier: bytes) -> list[Segment]:
        """
        Decrypts the encrypted segments of the URL stored within the object, using the specified main key
        and identifier. This operation is non-mutable.

        Returns:
            list[Segment]: A list of Segment objects, each representing a decrypted segment of the URL. The
                Segment class encapsulates both the decrypted content and the segment type.
        """
        if not self.path_segments:
            return []

        if self.is_shared_url():
            identifier = self._decrypt_shared_identifier(main_key)

        derived_key = self._derive_key(main_key, identifier)
        aessiv = self._get_encryptor(derived_key)

        decrypted_segments: list[Segment] = []
        for segment in self.path_segments:
            if segment.segment_type == SegmentType.ENCRYPTED:
                encrypted_segment = base64.urlsafe_b64decode(segment.value.encode())
                decrypted_segment = aessiv.decrypt(encrypted_segment, None).decode()
                decrypted_segments.append(
                    Segment(decrypted_segment, SegmentType.ENCRYPTED)
                )
            elif segment.segment_type == SegmentType.PLAIN:
                decrypted_segments.append(segment)

        return decrypted_segments

    def get_shareable_url(self, main_key: bytes, identifier: bytes) -> str:
        """Creates a shareable version of the currently stored URL. Non-mutable operation.

        Returns:
            str: The new shareable URL
        """
        if not self.path_segments:
            return ""
        if self.is_shared_url():
            return self.get_full_url()

        encryptor = self._get_encryptor(main_key)
        url = self.get_full_url()
        shareable_url = encryptor.encrypt(identifier, [url.encode()])
        shareable_url_base64 = base64.urlsafe_b64encode(shareable_url).decode()
        return f"{url}{self.DELIMITER}{self.SHARED_KEY_TYPE}{shareable_url_base64}{self.DELIMITER}"

    def _decrypt_shared_identifier(self, main_key: bytes) -> bytes:
        shared_identifier = self.path_segments[-1].value
        shared_identifier_bytes = base64.urlsafe_b64decode(shared_identifier.encode())
        aessiv = self._get_encryptor(main_key)
        aad = self.get_full_url(shared_segment=False).encode()
        return aessiv.decrypt(shared_identifier_bytes, [aad])

    @staticmethod
    @lru_cache(maxsize=1024)
    def encrypt_value(
        main_key: bytes, value: bytes, identifier: bytes, delimiter="~", shared=False
    ) -> str:
        """Encrypts a value with the main key and identifier.
        This function is indidirectly called by the middleware.

        Args:
            delimiter (str, optional): A string used to delimit encrypted segments within the resultant encrypted
                value. Defaults to "~", but can be customized based on requirements.
            shared (bool, optional): Whether the encrypted value should be shareable or not. Defaults to False.

        Returns:
            str: The encrypted representation of the value, including delimiters as specified.
        """
        derived_key = EncryptedURL._derive_key(main_key, identifier)
        encryptor = EncryptedURL._get_encryptor(derived_key)
        encrypted_value = encryptor.encrypt(value, None)
        encrypted_value_base64 = base64.urlsafe_b64encode(encrypted_value).decode()
        normal_value = f"{delimiter}{encrypted_value_base64}{delimiter}"

        if shared:
            shareable_value = EncryptedURL(normal_value, delimiter).get_shareable_url(
                main_key, identifier
            )
            return shareable_value

        return normal_value

    @staticmethod
    def _get_encryptor(derived_key: bytes) -> AESSIV:
        aessiv = AESSIV(derived_key)
        return aessiv

    @staticmethod
    @lru_cache(maxsize=1024)
    def _derive_key(main_key: bytes, identifier: bytes) -> bytes:
        kdf = HKDF(hashes.SHA256(), 32, None, b"encrypted-endpoints-fastapi")
        return kdf.derive(main_key + identifier)


class EncryptedEndpointsMiddleware:
    """EncryptedEndpointsMiddleware. Intercepts requests and decrypts the URL path and query parameters.
    Passes the decrypted URL back to the application.

        Args:
        app: The FastAPI application instance that the middleware is attached to. This is the application
             that will receive the decrypted URLs for handling.
        main_key (bytes): The key used to derive client-specific keys for encryption and decryption.

        templates (Optional, default=None): An optional Jinja2Templates instance to which the encryption
            function can be added. This allows for dynamic encryption of URLs within server-rendered templates.
            e.g.: templates from 'templates = Jinja2Templates(directory="templates")'

        encryption_function_name (str, optional): The name of the encryption function to be made available
            within Jinja templates for encrypting URL components. Defaults to "encrypt_value".

        identifier_extractor (Callable[[Request], bytes], optional): A function that extracts a client-specific
            identifier from the incoming request, such as an IP address or a session token.
            Defaults to extracting the client's IP address.

        pre_decrypt_filter_route (Callable[[str], bool], optional): A function to determine whether certain routes
            should bypass the decryption process. This is useful for paths that should remain unencrypted, such as
            static file routes or health check endpoints.

        url_validator (Callable[[list[Segment]], bool], optional): A function that validates the decrypted URL against
            certain criteria to ensure its integrity and validity. This can prevent malformed or maliciously crafted URLs
            from being processed by the application. Should be implemented when partial url encryption is supported.
            Then users could guess and use valid endpoints.

        delimiter (str, optional): The delimiter used to separate encrypted segments within the URL. This should be a
            character or sequence of characters that does not typically appear in URLs, to avoid conflicts. Defaults to "~".
    """

    def __init__(
        self,
        app,
        main_key: bytes,
        templates=None,
        encryption_function_name="encrypt_value",
        identifier_extractor: Callable[[Request], bytes] = None,
        pre_decrypt_filter_route: Callable[[str], bool] = None,
        url_validator: Callable[[list[Segment]], bool] = None,
        delimiter="~",
    ):
        self.app = app
        self.main_key = main_key
        self.delimiter = delimiter
        self.identifier_extractor = (
            identifier_extractor
            or EncryptedEndpointsMiddleware.default_extract_identifier
        )
        self.pre_decrypt_filter_route = (
            pre_decrypt_filter_route if pre_decrypt_filter_route else lambda x: False
        )
        self.url_validator = url_validator if url_validator else lambda x: False

        if templates:
            templates.env.globals[encryption_function_name] = self.encrypt_value

    async def __call__(self, scope, receive, send):
        if (
            scope["type"] != "http"
            or scope["path"] == "/favicon.ico"
            or self.pre_decrypt_filter_route(scope["path"])
        ):
            return await self.app(scope, receive, send)

        new_scope = scope.copy()
        request = Request(new_scope)

        try:
            encryptedURL = EncryptedURL(request.url.path, self.delimiter)

            identifier = self.identifier_extractor(request)
            url_segments = encryptedURL.decrypt_url(self.main_key, identifier)

            # Enforce that the path starts with a slash
            if url_segments and not url_segments[0].value.startswith("/"):
                url_segments[0].value = "/" + url_segments[0].value

            if self.url_validator(url_segments):
                return await self.app(new_scope, receive, send)

            path_and_query = "".join([segment.value for segment in url_segments])
            decrypted_url = urlparse(path_and_query)

            new_scope["path"] = decrypted_url.path or request.url.path
            new_scope["raw_path"] = new_scope["path"].encode()
            new_scope["query_string"] = decrypted_url.query.encode()

        except Exception as e:
            request = self.on_error(request, e)

        return await self.app(new_scope, receive, send)

    def encrypt_value(self, value: bytes, request: Request, shared=False) -> str:
        """Encrypts given value with the identifier of the request.
        This function is called from the Jinja2 template when specified.

        Returns:
            str: The encrypted value
        """
        if type(value) == int:
            value = str(value).encode()
        if type(value) == str:
            value = value.encode()

        identifier = self.identifier_extractor(request)
        return EncryptedURL.encrypt_value(
            self.main_key, value, identifier, self.delimiter, shared
        )

    @staticmethod
    def default_extract_identifier(request: Request) -> bytes:
        return request.client.host.encode()

    @staticmethod
    def on_error(request: Request, e: Exception) -> Request:
        traceback.print_exc()
        scope = request.scope.copy()
        scope["path"] = "/"
        return Request(scope)


"""
# Todo! Wait for FastAPI to support middleware on a per-router basis to have better granularity for including/excluding routes
https://github.com/tiangolo/fastapi/pull/11010/ (not our PR)

## Filtering routes
Till then filtering must be done in the middleware itself by giving a filter function to the middleware.
"""


class EncryptedRoute(APIRoute):
    def get_route_handler(self) -> Callable:
        original_route_handler = super().get_route_handler()

        async def encrypted_route_handler(request: Request) -> Response:
            return await original_route_handler(request)

        return encrypted_route_handler
