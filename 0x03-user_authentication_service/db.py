#!/usr/bin/env python3

"""DB module
"""
import bcrypt
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError


from user import Base, User


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """
        register new user
        """
        my_user = User(email=email, hashed_password=hashed_password)
        shesh = self._session
        shesh.add(my_user)
        shesh.commit()
        return my_user

    def find_user_by(self, **kwargs):
        """
        Search for user
        """
        shesh = self._session
        query = None
        dummy_user = User()
        for attr in kwargs.keys():
            if not hasattr(dummy_user, attr):
                raise InvalidRequestError
        for attr, val in kwargs.items():
            query = shesh.query(User).filter_by(**{attr: val})
        if query.count():
            return query.first()
        else:
            raise NoResultFound

    def update_user(self, user_id: int, **kwargs) -> None:
        """
        updates user information
        """
        try:
            user = self.find_user_by(id=user_id)
        except NoResultFound:
            raise ValueError
        shesh = self._session
        for attr, val in kwargs.items():
            setattr(user, attr, val)
        shesh.commit()

    def _hash_password(self, password: str) -> bytes:
        """
        encrypts a password
        """
        return bcrypt.hashpw(bytes(password, 'utf-8'), bcrypt.gensalt())
