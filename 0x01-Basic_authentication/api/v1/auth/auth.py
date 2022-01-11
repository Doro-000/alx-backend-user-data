#!/usr/bin/env python3
"""
Simple Authorization implementation
"""

from flask import request
from typing import List, TypeVar


class Auth:
    """
    Simple Authorization class
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        check if a path needs authorization
        """
        if not path or not excluded_paths:
            return True
        ProperPath = path + '/' if path[-1] != '/' else path
        if ProperPath not in excluded_paths:
            return True
        return False

    def authorization_header(self, request=None) -> str:
        """
        checks if the proper authorization is available in the request header
        """
        if not request:
            return None
        ReqHead = request.headers.get("Authorization")
        if not ReqHead:
            return None
        return ReqHead

    def current_user(self, request=None) -> TypeVar('User'):
        """
        gets the current user
        """
        return None
