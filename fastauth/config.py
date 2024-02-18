from __future__ import annotations
from logging import Logger
from typing import NamedTuple, ClassVar
from fastauth.log import logger as flogger


class FastAuthConfig:
    logger: ClassVar[Logger] = flogger
    debug: ClassVar[bool] = True

    @classmethod
    def get_defaults(cls) -> _DefaultParams:
        return _DefaultParams(debug=cls.debug, logger=cls.logger)

    @classmethod
    def set_defaults(cls, debug: bool, logger: Logger) -> None:
        cls.debug = debug
        cls.logger = logger


class _DefaultParams(NamedTuple):
    debug: bool
    logger: Logger
