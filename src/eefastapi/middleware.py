import base64
from typing import Callable

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import FastAPI, Request, Depends, Header
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response
from fastapi.templating import Jinja2Templates
import traceback


class EncryptedEndpointsMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        key: bytes,
        exclude_paths: list[str] = None,
        extract_identifier: Callable[[Request], bytes] = None,
    ):
        super().__init__(app)
        EncryptedEndpointsMiddleware.key = key
        EncryptedEndpointsMiddleware.extract_identifier = (
            extract_identifier or EncryptedEndpointsMiddleware.default_extract_identifier
        )
        print("CustomMiddleware initialized")

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        try:
            path, query = self.decrypt_request(request)

            # Modify request path and query string based on decrypted data
            scope = request.scope.copy()
            scope["path"] = path or request.url.path
            scope["query_string"] = query.encode() if query else request.url.query.encode()
            request = Request(scope)
        except Exception as e:
            request = self.on_error(request, e)

        response = await call_next(request)
        return response

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


app = FastAPI()
app.add_middleware(EncryptedEndpointsMiddleware, key=b"secret_key")

templates = Jinja2Templates(directory="templates")
templates.env.globals["encrypt_value"] = EncryptedEndpointsMiddleware.encrypt_value


@app.get("/")
async def read_root(request: Request):
    return templates.TemplateResponse("test.html", {"request": request})


@app.get("/some-route")
async def some_route(request: Request):
    print(request.url.path)
    return {"message": "This is some route"}


@app.get("/{full_path:path}")
async def catch_all(request: Request, full_path: str):
    print(request.url.path)
    return {"message": f"Caught all with path: {full_path}"}
