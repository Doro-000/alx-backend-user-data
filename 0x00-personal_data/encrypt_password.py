#!/usr/bin/env python3

"""
module for password hashing
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    hashes a password, adds a salt to the hash
    """
    password = bytes(password, 'utf-8')
    return bcrypt.hashpw(password, bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    validates password with hashed password
    """
    return bcrypt.checkpw(bytes(password, 'utf-8'), hashed_password)
