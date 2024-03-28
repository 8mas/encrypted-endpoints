import base64
import traceback
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import Request, Response
from fastapi.routing import APIRoute


class SegmentType(Enum):
    PLAIN = 1
    ENCRYPTED = 2
    SHARED_KEY = 3


@dataclass
class Segment:
    value: str
    segment_type: SegmentType


class EncryptedURL:
    SHARED_KEY_HEADER = "!"

    def __init__(self, full_path: str, DELIMITER: str = "~") -> None:
        self.DELIMITER = DELIMITER
        self.segments = self._parse_path(full_path)

    def _parse_path(self, full_path: str):
        if full_path and full_path[0] == "/":
            full_path = full_path[1:]

        segments = []
        # todo think about queries
        index = 0
        while index < len(full_path):
            if full_path[index] == self.DELIMITER:
                next_delimiter = full_path.find(self.DELIMITER, index + 1)
                if next_delimiter != -1:
                    segments.append(Segment(full_path[index + 1 : next_delimiter], SegmentType.ENCRYPTED))
                    index = next_delimiter + 1
                else:
                    break
            else:
                next_delimiter_or_end = full_path.find(self.DELIMITER, index)
                if next_delimiter_or_end != -1:
                    segments.append(Segment(full_path[index:next_delimiter_or_end], SegmentType.PLAIN))
                    index = next_delimiter_or_end
                else:
                    segments.append(Segment(full_path[index:], SegmentType.PLAIN))
                    index = len(full_path)
        if segments and segments[-1].value.startswith(self.SHARED_KEY_HEADER):
            segments[-1].value = segments[-1].value[1:]
            segments[-1].segment_type = SegmentType.SHARED_KEY

        return segments

    def get_full_url(self, shared_segment=True) -> str:
        url = ""
        for segment in self.segments:
            if segment.segment_type == SegmentType.ENCRYPTED:
                url += f"{self.DELIMITER}{segment.value}{self.DELIMITER}"
            elif segment.segment_type == SegmentType.PLAIN:
                url += segment.value
            elif segment.segment_type == SegmentType.SHARED_KEY and shared_segment:
                url += f"{self.DELIMITER}{self.SHARED_KEY_HEADER}{segment.value}{self.DELIMITER}"
        return url

    def is_shared_url(self):
        return self.segments and self.segments[-1].segment_type == SegmentType.SHARED_KEY

    def decrypt_url(self, main_key: bytes, identifier: bytes):
        if not self.segments:
            return []

        if self.is_shared_url():
            identifier = self._decrypt_shared_identifier(main_key)

        derived_key = self._derive_key(main_key, identifier)
        aessiv = self._get_encryptor(derived_key)

        decrypted_segments: list[Segment] = []
        for segment in self.segments:
            if segment.segment_type == SegmentType.ENCRYPTED:
                encrypted_segment = base64.urlsafe_b64decode(segment.value.encode())
                decrypted_segment = aessiv.decrypt(encrypted_segment, None).decode()
                decrypted_segments.append(Segment(decrypted_segment, SegmentType.ENCRYPTED))
            elif segment.segment_type == SegmentType.PLAIN:
                decrypted_segments.append(segment)

        return decrypted_segments  # todo really segements or just one string?

    def get_shareable_url(self, main_key: bytes, identifier: bytes) -> str:
        if not self.segments:
            return ""
        if self.is_shared_url():
            return self.get_full_url()

        encryptor = self._get_encryptor(main_key)
        url = self.get_full_url()
        shareable_url = encryptor.encrypt(identifier, [url.encode()])
        shareable_url_base64 = base64.urlsafe_b64encode(shareable_url).decode()
        return f"{url}{self.DELIMITER}{self.SHARED_KEY_HEADER}{shareable_url_base64}{self.DELIMITER}"

    def _decrypt_shared_identifier(self, main_key: bytes) -> bytes:
        shared_identifier = self.segments[-1].value
        shared_identifier_bytes = base64.urlsafe_b64decode(shared_identifier.encode())
        aessiv = self._get_encryptor(main_key)
        aad = self.get_full_url(shared_segment=False).encode()
        return aessiv.decrypt(shared_identifier_bytes, [aad])

    @staticmethod
    def encrypt_value(main_key: bytes, value: bytes, identifier: bytes, delimiter="~") -> str:
        derived_key = EncryptedURL._derive_key(main_key, identifier)
        encryptor = EncryptedURL._get_encryptor(derived_key)
        encrypted_value = encryptor.encrypt(value, None)
        encrypted_value_base64 = base64.urlsafe_b64encode(encrypted_value).decode()
        return f"{delimiter}{encrypted_value_base64}{delimiter}"

    @staticmethod
    def _get_encryptor(derived_key: bytes) -> AESSIV:
        aessiv = AESSIV(derived_key)
        return aessiv

    @staticmethod
    def _derive_key(main_key: bytes, identifier: bytes) -> bytes:
        kdf = HKDF(hashes.SHA256(), 32, None, b"encrypted-endpoints-fastapi")
        return kdf.derive(main_key + identifier)


# TODO support for link sharing & Session ressumption
# TODO support for query parameters
# TODO support for javascript
# TODO implement mac only mode
class EncryptedEndpointsMiddleware:
    def __init__(
        self,
        app,
        main_key: bytes,
        templates=None,
        encryption_function_name="encrypt_value",
        identifier_extractor: Callable[[Request], bytes] = None,
        filter_route: Callable[[str], bool] = None,
        delimiter="~",
    ):
        self.app = app
        self.main_key = main_key
        self.delimiter = delimiter
        self.identifier_extractor = identifier_extractor or EncryptedEndpointsMiddleware.default_extract_identifier
        self.filter_route = filter_route if filter_route else lambda x: False

        if templates:
            templates.env.globals[encryption_function_name] = self.encrypt_value

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if scope["path"] == "/favicon.ico":
            return await self.app(scope, receive, send)
        if self.filter_route(scope["path"]):
            return await self.app(scope, receive, send)

        new_scope = scope.copy()
        request = Request(new_scope)

        try:
            encryptedURL = EncryptedURL(request.url.path, self.delimiter)

            test = encryptedURL.get_shareable_url(self.main_key, self.identifier_extractor(request))
            encryptedURL = EncryptedURL(test, self.delimiter)

            identifier = self.identifier_extractor(request)
            path_segments = encryptedURL.decrypt_url(self.main_key, identifier)

            if path_segments and not path_segments[0].value.startswith("/"):
                path_segments[0].value = "/" + path_segments[0].value
            # todo! check here if path and query are in allowed route

            path = "".join([segment.value for segment in path_segments])
            new_scope["path"] = path or request.url.path
            new_scope["raw_path"] = new_scope["path"].encode()
        except Exception as e:
            request = self.on_error(request, e)

        return await self.app(new_scope, receive, send)

    def encrypt_value(self, value: bytes, request: Request) -> str:
        if type(value) == str:
            value = value.encode()

        identifier = self.identifier_extractor(request)
        return EncryptedURL.encrypt_value(self.main_key, value, identifier, self.delimiter)

    @staticmethod
    def default_extract_identifier(request: Request):
        return request.client.host.encode()

    @staticmethod
    def on_error(request: Request, e: Exception) -> Request:
        traceback.print_exc()
        scope = request.scope.copy()
        scope["path"] = "/"
        return Request(scope)


class EncryptedRoute(APIRoute):
    def get_route_handler(self) -> Callable:
        original_route_handler = super().get_route_handler()

        async def encrypted_route_handler(request: Request) -> Response:
            print("Encrypted Route Handler")
            return await original_route_handler(request)

        return encrypted_route_handler


"""
# Todo! Wait for FastAPI to support middleware on a per-router basis to have better granularity for including/excluding routes
https://github.com/tiangolo/fastapi/pull/11010/ (not our PR)

## Filtering routes
Till then filtering must be done in the middleware itself by giving a filter function to the middleware.
"""
