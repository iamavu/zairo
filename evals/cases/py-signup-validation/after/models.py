import itertools
from dataclasses import dataclass

from werkzeug.security import generate_password_hash

_ids = itertools.count(1)
_users = {}


@dataclass
class User:
    id: int
    email: str
    password_hash: str

    @staticmethod
    def create(email, password):
        user = User(id=next(_ids), email=email, password_hash=generate_password_hash(password))
        _users[user.id] = user
        return user
