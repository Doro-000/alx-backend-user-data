#!/usr/bin/env python3

"""
Simple Authorization implementation
"""

from base64 import b64decode as decode
from api.v1.auth.auth import Auth
from typing import TypeVar, Tuple
from models.user import User


class BasicAuth(Auth):
    """
    Simple Authorization class
    """

    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """
        extracts encoded authorization header
        """
        if not authorization_header:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """
        decodes Base64 authorization header
        """
        if not base64_authorization_header:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            return decode(base64_authorization_header).decode('utf-8')
        except BaseException:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> Tuple[str, str]:
        """
        finds neccessary user data
        """
        if not decoded_base64_authorization_header:
            return (None, None)
        if not isinstance(decoded_base64_authorization_header, str):
            return (None, None)
        if ':' not in decoded_base64_authorization_header:
            return (None, None)
        return tuple(decoded_base64_authorization_header.split(":"))

    def user_object_from_credentials(
            self,
            user_email: str,
            user_pwd: str) -> TypeVar('User'):
        """
        searches for user based on user email and password
        """
        if not user_email or not isinstance(user_email, str):
            return None
        if not user_pwd or not isinstance(user_pwd, str):
            return None
        if User.count() == 0:
            return None
        usr = User.search({"email": user_email})
        if not usr:
            return None
        if not usr[0].is_valid_password(user_pwd):
            return None
        return usr[0]

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the current user
        """
        authorization_header = self.authorization_header(request)
        encoded_authorize_header = self.extract_base64_authorization_header(
            authorization_header)
        decoded_authorization_header = self.decode_base64_authorization_header(
            encoded_authorize_header)
        usr_credentials = self.extract_user_credentials(
            decoded_authorization_header)
        usr_email = usr_credentials[0]
        usr_pwd = usr_credentials[1]
        usr = self.user_object_from_credentials(usr_email, usr_pwd)
        return usr
