#!/usr/bin/env python3

"""
session authentication
"""

from api.v1.auth.auth import Auth
from uuid import uuid4
from models.user import User


class SessionAuth(Auth):
    """
    session authentication implementation
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
        creates a session Id for a user
        """
        if not user_id or not isinstance(user_id, str):
            return None
        usr_id = str(uuid4())
        SessionAuth.user_id_by_session_id[usr_id] = user_id
        return usr_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        returns user_id based on session_id
        """
        if not session_id or not isinstance(session_id, str):
            return None
        return SessionAuth.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """
        returns user based on cookie value
        """
        sesh_cookie = self.session_cookie(request)
        usr_id = self.user_id_for_session_id(sesh_cookie)
        return User.get(usr_id)

    def destroy_session(self, request=None):
        """
        logout user
        """
        if not request:
            return False
        sesh_cookie = self.session_cookie(request)
        if not sesh_cookie:
            return False
        usr_id = self.user_id_for_session_id(sesh_cookie)
        if not usr_id:
            return False
        SessionAuth.user_id_by_session_id.pop(sesh_cookie)
        return True
