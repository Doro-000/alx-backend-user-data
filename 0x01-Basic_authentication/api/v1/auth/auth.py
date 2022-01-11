#!/usr/bin/env python3


from flask import request
from typing import List, TypeVar


class Auth:
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        if not path or not excluded_paths:
            return True
        ProperPath = path + '/' if path[-1] != '/' else path
        if ProperPath not in excluded_paths:
            return True
        return False

    def authorization_header(self, request=None) -> str:
        if not request:
            return None
        ReqHead = request.headers.get("Authorization")
        if not ReqHead:
            return None
        return ReqHead

    def current_user(self, request=None) -> TypeVar('User'):
        return None
