from fastapi import APIRouter, FastAPI, Request
from fastapi.templating import Jinja2Templates
from middleware import EncryptedEndpointsMiddleware, EncryptedRoute

templates = Jinja2Templates(directory="templates")
app = FastAPI()

app.add_middleware(
    middleware_class=EncryptedEndpointsMiddleware,
    main_key=b"0" * 64,
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
