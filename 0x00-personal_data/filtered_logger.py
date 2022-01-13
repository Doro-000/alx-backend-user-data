#!/usr/bin/env python3

"""
logging with sensitive information redaction
"""

from typing import List, Tuple
import re
import logging
from mysql.connector import connection
from os import getenv


PII_FIELDS: Tuple[str] = ("ssn", "password", "name", "email", "phone")


def filter_datum(fields: List[str], blur: str, msg: str, sep: str) -> str:
    """ redact sensitive info """
    blurred: List[str] = [re.sub(r'(.+=)(.+)', r'\1' + blur, pair)
                          if pair.split('=')[0] in fields
                          else pair for pair in msg.split(sep)]
    return sep.join(blurred)


def get_logger() -> logging.Logger:
    """
    get a logger object
    """
    formatter: logging.Formatter = RedactingFormatter(PII_FIELDS)

    handler: logging.Handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    my_logger: logging.Logger = logging.getLogger("user_data")
    my_logger.setLevel(logging.INFO)
    my_logger.propagate = False
    my_logger.addHandler(handler)

    return my_logger


def get_db() -> connection.MySQLConnection:
    """
    get a connection to a db
    """
    usr_name: str = getenv("PERSONAL_DATA_DB_USERNAME")
    usr_pass: str = getenv("PERSONAL_DATA_DB_PASSWORD")
    db_host: str = getenv("PERSONAL_DATA_DB_HOST")
    db_name: str = getenv("PERSONAL_DATA_DB_NAME")
    return connection.MySQLConnection(
        user=usr_name,
        password=usr_pass,
        host=db_host,
        database=db_name)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION: str = "***"
    FORMAT: str = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"  # nopep8
    SEPARATOR: str = ";"

    def __init__(self, fields: List[str]):
        """
        initialization
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields: List[str] = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        redact message and format log
        """
        filtered_message: str = filter_datum(
            self.fields,
            self.REDACTION,
            record.getMessage(),
            self.SEPARATOR)
        record.msg = filtered_message
        return super(RedactingFormatter, self).format(record)


def main() -> None:
    """
    Entry point
    """
    my_connection: connection.MySQLConnection = get_db()
    my_cursor: connection.MySQLConnection.cursor = my_connection.cursor()
    my_cursor.execute("SELECT * FROM users;")

    my_logger: logging.Logger = get_logger()
    for row in my_cursor:
        row = map(str, row)
        temp = zip(
            ("name",
             "email",
             "phone",
             "ssn",
             "password",
             "ip",
             "last_login",
             "user_agent"),
            row)
        message: str = ";".join(["=".join(pair) for pair in temp])
        my_logger.info(message)


if __name__ == "__main__":
    main()
