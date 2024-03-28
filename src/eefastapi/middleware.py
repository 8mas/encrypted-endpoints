import base64
import traceback
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import APIRouter, FastAPI, Request, Response
from fastapi.routing import APIRoute
from fastapi.templating import Jinja2Templates


def _get_encryptor(derived_key: bytes) -> AESSIV:
    aessiv = AESSIV(derived_key)
    return aessiv


def _derive_key(main_key: bytes, identifier: bytes) -> bytes:
    kdf = HKDF(hashes.SHA256(), 32, None, b"encrypted-endpoints-fastapi")
    return kdf.derive(main_key + identifier)


class SegmentType(Enum):
    PLAIN = 1
    ENCRYPTED = 2
    SHARED_KEY = 3


@dataclass
class Segment:
    value: str
    segment_type: SegmentType


@dataclass(init=False)
class EncryptedURL:
    segments: list[Segment] = field(default_factory=list)

    def __init__(self, full_path: str, DELIMITER: str = "~") -> None:
        self.segments = []
        self.DELIMITER = DELIMITER

        path = full_path[1:]  # Remove leading /
        # todo think about queries
        index = 0
        while index < len(path):
            if path[index] == self.DELIMITER:
                next_tilde = path.find(self.DELIMITER, index + 1)
                if next_tilde != -1:
                    self.segments.append(Segment(path[index + 1 : next_tilde], SegmentType.ENCRYPTED))
                    index = next_tilde + 1
                else:
                    break
            else:
                next_tilde_or_end = path.find(self.DELIMITER, index)
                if next_tilde_or_end != -1:
                    self.segments.append(Segment(path[index:next_tilde_or_end], SegmentType.PLAIN))
                    index = next_tilde_or_end
                else:
                    self.segments.append(Segment(path[index:], SegmentType.PLAIN))
                    index = len(path)
        if self.segments and self.segments[-1].value.startswith("!"):
            self.segments[-1].value = self.segments[-1].value[1:]
            self.segments[-1].segment_type = SegmentType.SHARED_KEY

    def is_shared_url(self):
        return self.segments and self.segments[-1].segment_type == SegmentType.SHARED_KEY

    def decrypt_url(self, main_key: bytes, identifier: bytes):
        derived_key = _derive_key(main_key, identifier)
        aessiv = _get_encryptor(derived_key)
        if not self.segments:
            return []

        decrypted_segments: list[Segment] = []
        for segment in self.segments:
            if segment.segment_type == SegmentType.ENCRYPTED:
                encrypted_segment = base64.urlsafe_b64decode(segment.value.encode())
                decrypted_segment = aessiv.decrypt(encrypted_segment, None).decode()
                decrypted_segments.append(Segment(decrypted_segment, SegmentType.ENCRYPTED))
            else:
                decrypted_segments.append(segment)

        return decrypted_segments  # todo really segements or just one string?

    @staticmethod
    def encrypt_value(main_key: bytes, value: bytes, identifier: bytes, DELIMITER="~") -> str:
        derived_key = _derive_key(main_key, identifier)
        encryptor = _get_encryptor(derived_key)
        encrypted_value = encryptor.encrypt(value, None)
        encrypted_value_base64 = base64.urlsafe_b64encode(encrypted_value).decode()
        return f"{DELIMITER}{encrypted_value_base64}{DELIMITER}"

    def make_url_shareable(self, url: str, request: Request) -> str:
        """
        [encrypt URL]__AE(key, authenticated data)

        """
        pass

    def decrypt_url_identifier(self, encrypted_url, main_key: bytes):
        if not encrypted_url.is_shared_url():
            return None

        path_aad = "".join([segment.value for segment in encrypted_url.segments[:-1]])  # Except the last segment (key)
        decryptor = AESSIV(main_key)
        identifier = decryptor.decrypt(encrypted_url.segments[-1].value.encode(), path_aad.encode())


# TODO refactor all crypto operations to EncryptedULR class
# TODO use functools and partial to create a function for jinja2
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
            identifier = self.identifier_extractor(request)
            path_segments = encryptedURL.decrypt_url(self.main_key, identifier)

            if path_segments and not path_segments[0].value.startswith("/"):
                path_segments[0].value = "/" + path_segments[0].value
            # todo! check here if path and query are in allowed route

            path = "".join([segment.value for segment in path_segments])
            new_scope["path"] = path or request.url.path
            new_scope["raw_path"] = new_scope["path"]
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

templates = Jinja2Templates(directory="templates")
app = FastAPI()

app.add_middleware(
    middleware_class=EncryptedEndpointsMiddleware,
    main_key=b"secret_key",
    templates=templates,
)  # Set middleware global. This will encrypt all routes. See above for more granular control.

encrypted_endpoint = APIRouter(route_class=EncryptedRoute)


@encrypted_endpoint.get("/encrypted-route")
async def encrypted_route(request: Request):
    return {"message": "Encrypted-route"}


@encrypted_endpoint.get("/")
async def read_root(request: Request):
    return templates.TemplateResponse("test.html", {"request": request})


@encrypted_endpoint.get("/encrypted/route/but/only/partial")
async def partial_encrypted_route(request: Request):
    return {"message": "partial encrypted route"}


# Since we have a catch-all route, we need to add the encrypted route first
app.include_router(router=encrypted_endpoint)


@app.get("/clear-route")
async def clear_route(request: Request):
    return {"message": "clear-route"}


@app.get("/{full_path:path}")
async def catch_all(request: Request, full_path: str):
    return {"message": f"GENERIC CATCH: {full_path}"}
