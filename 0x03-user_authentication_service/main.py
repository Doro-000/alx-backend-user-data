#!/usr/bin/env python3
"""
test api
"""

import requests
from json import dumps

BASEURL = "http://0.0.0.0:5000"
EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


def register_user(email: str, password: str) -> None:
    """
    test register user
    """
    response = requests.post(
        BASEURL + "/users",
        data={
            "email": email,
            "password": password})
    assert(response.json() == dumps(
        {"email": email, "message": "user created"}))
    assert(response.status_code == 200)


def log_in_wrong_password(email: str, password: str) -> None:
    """
    test invalid login
    """
    response = requests.post(
        BASEURL + "/sessions",
        data={
            "email": email,
            "password": password})
    assert(response.status_code == 401)


def log_in(email: str, password: str) -> str:
    """
    test valid login
    """
    response = requests.post(
        BASEURL + "/sessions",
        data={
            "email": email,
            "password": password})
    assert(response.json() == dumps({"email": email, "message": "logged in"}))
    assert(response.status_code == 200)


def log_out(session_id: str) -> None:
    """
    test logout
    """
    pass


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    # profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    # profile_logged(session_id)
    log_out(session_id)
    # reset_token = reset_password_token(EMAIL)
    # update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
