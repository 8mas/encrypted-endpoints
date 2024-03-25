from html import escape
from pprint import pprint
from typing import Annotated, Optional
from uuid import uuid4

from fastapi import Cookie, Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, field_validator, model_validator

app = FastAPI()


templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


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


class User(BaseModel):
    username: str
    password: str


class Vote(BaseModel):
    post_id: str
    user_vote: int


users: dict[str, User] = {}
posts: dict[str, Post] = {}

votes = set()


d1 = Post(
    id=str(uuid4()),
    author="Reviewer1",
    title="This seems useful",
    content="This looks like a really useful example of your approach",
    votes=1,
)

d2 = Post(
    id=str(uuid4()),
    author="Reviewer2",
    title="Rejected",
    content="I'm sorry, but I don't think this is a good approach",
    votes=-2,
)

posts[d1.id] = d1  # type: ignore
posts[d2.id] = d2  # type: ignore


def get_current_user(
    username: Annotated[str | None, Cookie()] = None, password: Annotated[str | None, Cookie()] = None
):
    user = None
    if username in users and users[username].password == password:
        user = users[username]
    return user


@app.get("/")
def get_start_page(request: Request, user: User = Depends(get_current_user)):
    current_user = user.model_dump() if user else None
    return templates.TemplateResponse(
        "start_page.html", {"request": request, "user": current_user, "posts": list(posts.values())}
    )


@app.post("/auth/")
def auth(username: str = Form(...), password: str = Form(...)) -> RedirectResponse:
    user = users.get(username)
    if user and user.password != password:
        return RedirectResponse(url="/", status_code=status.HTTP_401_UNAUTHORIZED)
    elif user is None:
        users[username] = User(username=username, password=password)
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.set_cookie(key="username", value=username)
    response.set_cookie(key="password", value=password)
    return response


@app.get("/posts/")
def get_posts(user: User = Depends(get_current_user)):
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    pprint(posts)
    return {"posts": list(posts.values())}


@app.get("/posts/{post_id}")
def get_post(post_id: str, user: User = Depends(get_current_user)):
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    post = posts.get(post_id)
    if post is None:
        raise HTTPException(status_code=404, detail="Post not found")
    return post


@app.post("/posts/", response_model=Post)
def create_post(post: Post, user: User = Depends(get_current_user)):
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    pprint(post)

    post.id = str(uuid4())
    post.author = user.username
    post.votes = 0
    posts[post.id] = post
    pprint(post)
    return post


@app.post("/vote/")
def vote_post(vote: Vote, user: User = Depends(get_current_user)) -> int:
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if vote.user_vote not in (-1, 1):
        raise HTTPException(status_code=400, detail="Invalid vote")
    if vote.post_id not in posts:
        raise HTTPException(status_code=404, detail="Post not found")
    if (user.username, vote.post_id) in votes:
        raise HTTPException(status_code=400, detail="Already voted")
    votes.add((user.username, vote.post_id))

    post = posts.get(vote.post_id)
    if post is None:
        raise HTTPException(status_code=404, detail="Post not found")

    post.votes += vote.user_vote
    return post.votes


@app.get("/logout/")
def logout():
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.delete_cookie(key="username")
    response.delete_cookie(key="password")
    return response
