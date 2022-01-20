#!/usr/bin/env python3
"""
test api
"""

from urllib import response
import requests

BASEURL = "http://127.0.0.1:5000"
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
    assert(response.json() ==
           {"email": email, "message": "user created"})
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
    assert(response.json() == {"email": email, "message": "logged in"})
    assert(response.status_code == 200)
    return response.cookies.get("session_id")


def log_out(session_id: str) -> None:
    """
    test logout
    """
    response = requests.delete(
        BASEURL + "/sessions",
        cookies={
            "session_id": session_id})
    assert(response.status_code == 200)
    assert(response.url == BASEURL + '/')
    redirect = response.history[0]
    assert(redirect.status_code == 302)


def profile_unlogged() -> None:
    """
    test user not logged in
    """
    response = requests.get(BASEURL + "/profile")
    assert(response.status_code == 403)


def profile_logged(session_id: str) -> None:
    """
    test user logged in
    """
    response = requests.get(
        BASEURL + "/profile",
        cookies={
            "session_id": session_id})
    assert(response.status_code == 200)
    assert(response.json() == {"email": response.json().get("email")})


def reset_password_token(email: str) -> str:
    """
    password reset test
    """
    response = requests.post(
        BASEURL +
        "/reset_password",
        data={
            "email": email})
    assert(response.status_code == 200)
    assert("reset_token" in response.json().keys())
    assert(response.json().get("email") == email)
    return response.json()["reset_token"]


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """
    test update password
    """
    response = requests.put(
        BASEURL + "/reset_password",
        data={
            "email": email,
            "reset_token": reset_token,
            "new_password": new_password})
    assert(response.status_code == 200)
    assert(response.json() == {"email": email, "message": "Password updated"})


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
