from typing import Annotated, Optional

from fastapi import HTTPException, Cookie, Depends, FastAPI, Form, Request, status
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, field_validator, model_validator
from uuid import uuid4
from pprint import pprint
from html import escape


app = FastAPI()


templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

users = {}
posts = []

votes = set()


class Post(BaseModel):
    id: Optional[str] = None
    title: str
    content: str
    author: Optional[str] = None
    votes: int = 0

    @field_validator("title", "content", "author")
    @classmethod
    def escape_html(cls, value):
        return escape(value)


class Vote(BaseModel):
    user_id: str
    post_id: str
    vote: int  # 1 for upvote, -1 for downvote


posts.append(
    Post(
        id=str(uuid4()),
        author="Reviewer1",
        title="This seems useful",
        content="This looks like a really useful example of your approach",
        votes=1,
    )
)
posts.append(
    Post(
        id=str(uuid4()),
        author="Reviewer2",
        title="Rejected",
        content="I'm sorry, but I don't think this is a good approach",
        votes=-2,
    )
)


def get_current_user(
    username: Annotated[str | None, Cookie()] = None, password: Annotated[str | None, Cookie()] = None
):
    user = None
    if username in users and users[username]["password"] == password:
        user = users[username]
    return user


@app.get("/")
def get_start_page(request: Request, user: Optional[dict] = Depends(get_current_user)):
    return templates.TemplateResponse("start_page.html", {"request": request, "user": user, "posts": posts})


@app.post("/auth/")
def auth(username: str = Form(...), password: str = Form(...)) -> RedirectResponse:
    user = users.get(username)
    if user and user["password"] != password:
        return RedirectResponse(url="/", status_code=status.HTTP_401_UNAUTHORIZED)
    elif user is None:
        users[username] = {"username": username, "password": password}
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.set_cookie(key="username", value=username)
    response.set_cookie(key="password", value=password)
    return response


@app.get("/posts/")
def get_posts(user: Optional[dict] = Depends(get_current_user)):
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    pprint(posts)
    return {"posts": posts}


@app.post("/posts/", response_model=Post)
def create_post(post: Post, user: Optional[dict] = Depends(get_current_user)):
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    pprint(post)

    post.id = str(uuid4())
    post.author = user["username"]
    post.votes = 0
    posts.append(post.model_dump())
    pprint(post)
    return post
