#!/usr/bin/env python3
"""
Module for Authentication
"""


from db import DB
from user import User
import bcrypt
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4
from typing import Union


def _hash_password(password: str) -> bytes:
    """
    encrypts a password
    """
    return bcrypt.hashpw(bytes(password, 'utf-8'), bcrypt.gensalt())


def _generate_uuid() -> str:
    """
    generate unique id
    """
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """
        initialization
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        register new user
        """
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            hashed_pass = _hash_password(password)
            return self._db.add_user(email, hashed_pass)
        raise ValueError("User {} already exists".format(email))

    def valid_login(self, email, password) -> bool:
        """
        validates user password
        """
        try:
            usr = self._db.find_user_by(email=email)
            return bcrypt.checkpw(
                bytes(
                    password,
                    'utf-8'),
                usr.hashed_password)
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """
        create a new session
        """
        try:
            usr = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(usr.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> Union(User, None):
        """
        retrive user using session id
        """
        if not session_id:
            return None
        try:
            usr = self._db.find_user_by(session_id=session_id)
            return usr
        except BaseException:
            return None

    def destroy_session(self, user_id: str) -> None:
        """
        delete session
        """
        try:
            self._db.update_user(user_id, session_id=None)
        except BaseException:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """
        Generate reset password token
        """
        try:
            usr = self._db.find_user_by(email=email)
            token = _generate_uuid()
            self._db.update_user(usr.id, reset_token=token)
            return token
        except NoResultFound:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """
        update user password
        """
        try:
            usr = self._db.find_user_by(reset_token=reset_token)
            new_pass = _hash_password(password)
            self._db.update_user(
                usr.id,
                hashed_password=new_pass,
                reset_token=None)
        except NoResultFound:
            raise ValueError
