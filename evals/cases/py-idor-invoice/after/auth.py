import functools

from flask import abort, g, request

from models import User


def login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        g.user = User.from_token(token)
        if g.user is None:
            abort(401)
        return view(*args, **kwargs)

    return wrapper
