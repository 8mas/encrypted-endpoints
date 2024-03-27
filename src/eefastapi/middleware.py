import base64
import traceback
from typing import Callable

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import APIRouter, Depends, FastAPI, Header, Request, Response
from fastapi.templating import Jinja2Templates
from fastapi.routing import APIRoute


class EncryptedEndpointsMiddleware:
    def __init__(
        self,
        app,
        key: bytes,
        exclude_paths: list[str] = None,
        extract_identifier: Callable[[Request], bytes] = None,
    ):
        self.app = app
        EncryptedEndpointsMiddleware.key = key
        EncryptedEndpointsMiddleware.extract_identifier = (
            extract_identifier or EncryptedEndpointsMiddleware.default_extract_identifier
        )

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if scope["path"] == "/favicon.ico":
            return await self.app(scope, receive, send)

        new_scope = scope.copy()
        request = Request(new_scope)

        try:
            path, query = self.decrypt_request(request)
            new_scope["path"] = path or request.url.path
            new_scope["raw_path"] = new_scope["path"]
            new_scope["query_string"] = query.encode() if query else request.url.query.encode()
        except Exception as e:
            request = self.on_error(request, e)

        return await self.app(new_scope, receive, send)

    @classmethod
    def decrypt_request(cls, request: Request) -> tuple[str, str]:
        aessiv = cls._get_encryptor(request)
        path = request.url.path[1:]  # Remove leading /
        query = request.url.query
        if path:
            base64_path = base64.urlsafe_b64decode(path.encode())
            path = aessiv.decrypt(base64_path, None).decode()
        if query:
            query = aessiv.decrypt(base64.urlsafe_b64decode(query.encode()), None).decode()
        return path, query

    @staticmethod
    def encrypt_value(value: str, request: Request) -> str:
        encryptor = EncryptedEndpointsMiddleware._get_encryptor(request)
        encrypted_value = encryptor.encrypt(value.encode(), None)
        encrypted_value_base64 = base64.urlsafe_b64encode(encrypted_value).decode()
        return encrypted_value_base64

    @classmethod
    def _get_encryptor(cls, request: Request) -> AESSIV:
        identifier = cls.extract_identifier(request)
        derived_key = cls._derive_key(identifier=identifier)
        aessiv = AESSIV(derived_key)
        return aessiv

    @classmethod
    def _derive_key(cls, identifier: bytes) -> bytes:
        kdf = HKDF(hashes.SHA256(), 32, None, b"encrypted-endpoints-fastapi")
        return kdf.derive(EncryptedEndpointsMiddleware.key + identifier)

    @staticmethod
    def default_extract_identifier(request: Request) -> bytes:
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


app = FastAPI()
encrypted_endpoint = APIRouter(route_class=EncryptedRoute)

app.add_middleware(middleware_class=EncryptedEndpointsMiddleware, key=b"secret_key")

templates = Jinja2Templates(directory="templates")
templates.env.globals["encrypt_value"] = EncryptedEndpointsMiddleware.encrypt_value


@encrypted_endpoint.get("/encrypted-route")
async def encrypted_route(request: Request):
    return {"message": "Encrypted-route"}


@encrypted_endpoint.get("/")
async def read_root(request: Request):
    return templates.TemplateResponse("test.html", {"request": request})


app.include_router(router=encrypted_endpoint)


@app.get("/clear-route")
async def clear_route(request: Request):
    return {"message": "clear-route"}


@app.get("/{full_path:path}")
async def catch_all(request: Request, full_path: str):
    return {"message": f"GENERIC CATCH: {full_path}"}
