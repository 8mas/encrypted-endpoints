import base64
import traceback
from dataclasses import dataclass
from typing import Callable

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import APIRouter, Depends, FastAPI, Header, Request, Response
from fastapi.routing import APIRoute
from fastapi.templating import Jinja2Templates


@dataclass
class Segment:
    value: str
    encrypted: bool


class EncryptedEndpointsMiddleware:
    def __init__(
        self,
        app,
        key: bytes,
        identifier_extractor: Callable[[Request], bytes] = None,
        filter_route: Callable[[str], bool] = None,
        DELIMITER: str = "~",
    ):
        self.app = app
        EncryptedEndpointsMiddleware.key = key
        EncryptedEndpointsMiddleware.identifier_extractor = (
            identifier_extractor or EncryptedEndpointsMiddleware.default_extract_identifier
        )
        EncryptedEndpointsMiddleware.filter_route = filter_route if filter_route else lambda x: False
        EncryptedEndpointsMiddleware.DELIMITER = DELIMITER

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if scope["path"] == "/favicon.ico":
            return await self.app(scope, receive, send)
        if EncryptedEndpointsMiddleware.filter_route(scope["path"]):
            return await self.app(scope, receive, send)

        new_scope = scope.copy()
        request = Request(new_scope)

        try:
            url_segments = self._parse_url_segments(request)
            path_segments, query = self.decrypt_request(url_segments, request)

            if path_segments and not path_segments[0].value.startswith("/"):
                path_segments[0].value = "/" + path_segments[0].value
            # todo! check here if path and query are in allowed route

            path = "".join([segment.value for segment in path_segments])

            new_scope["path"] = path or request.url.path
            new_scope["raw_path"] = new_scope["path"]
            new_scope["query_string"] = query.encode() if query else request.url.query.encode()
        except Exception as e:
            request = self.on_error(request, e)

        return await self.app(new_scope, receive, send)

    @classmethod
    def decrypt_request(cls, url_segments: list[Segment], request: Request) -> tuple[list[Segment], list[Segment]]:
        aessiv = cls._get_encryptor(request)
        if not url_segments:
            return request.url.path, request.url.query

        decrypted_segments: list[Segment] = []
        for segment in url_segments:
            if segment.encrypted:
                encrypted_segment = base64.urlsafe_b64decode(segment.value.encode())
                decrypted_segment = aessiv.decrypt(encrypted_segment, None).decode()
                decrypted_segments.append(Segment(decrypted_segment, encrypted=True))
            else:
                decrypted_segments.append(segment)

        return decrypted_segments, request.url.query

    @staticmethod
    def encrypt_value(value: str, request: Request) -> str:
        encryptor = EncryptedEndpointsMiddleware._get_encryptor(request)
        encrypted_value = encryptor.encrypt(value.encode(), None)
        encrypted_value_base64 = base64.urlsafe_b64encode(encrypted_value).decode()
        return (
            f"{EncryptedEndpointsMiddleware.DELIMITER}{encrypted_value_base64}{EncryptedEndpointsMiddleware.DELIMITER}"
        )

    @classmethod
    def _get_encryptor(cls, request: Request) -> AESSIV:
        identifier = cls.identifier_extractor(request)
        derived_key = cls._derive_key(identifier=identifier)
        aessiv = AESSIV(derived_key)
        return aessiv

    @classmethod
    def _derive_key(cls, identifier: bytes) -> bytes:
        kdf = HKDF(hashes.SHA256(), 32, None, b"encrypted-endpoints-fastapi")
        return kdf.derive(cls.key + identifier)

    @staticmethod
    def default_extract_identifier(request: Request) -> bytes:
        return request.client.host.encode()

    @staticmethod
    def _parse_url_segments(request: Request) -> list[Segment]:
        path = request.url.path[1:]  # Remove leading /
        query = request.url.query
        url_string = path  # + query # todo think later about this

        parsed_segments = []
        index = 0
        while index < len(path):
            if path[index] == "~":
                next_tilde = path.find("~", index + 1)
                if next_tilde != -1:
                    parsed_segments.append(Segment(path[index + 1 : next_tilde], encrypted=True))
                    index = next_tilde + 1
                else:
                    break
            else:
                next_tilde_or_end = path.find("~", index)
                if next_tilde_or_end != -1:
                    parsed_segments.append(Segment(path[index:next_tilde_or_end], encrypted=False))
                    index = next_tilde_or_end
                else:
                    parsed_segments.append(Segment(path[index:], encrypted=False))
                    index = len(path)

        return parsed_segments

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

app = FastAPI()
app.add_middleware(
    middleware_class=EncryptedEndpointsMiddleware, key=b"secret_key"
)  # Set middleware global. This will encrypt all routes. See above for more granular control.


encrypted_endpoint = APIRouter(route_class=EncryptedRoute)

templates = Jinja2Templates(directory="templates")
templates.env.globals["encrypt_value"] = EncryptedEndpointsMiddleware.encrypt_value


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
