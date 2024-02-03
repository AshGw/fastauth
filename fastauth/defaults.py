from logging import Logger
from typing import NamedTuple, ClassVar
from fastauth.log import logger as flogger


class DefaultParams(NamedTuple):
    debug: bool
    logger: Logger


class Defaults:
    _logger: ClassVar[Logger] = flogger
    _debug: ClassVar[bool] = True

    @classmethod
    def get_logger(cls) -> Logger:
        return cls._logger

    @classmethod
    def get_debug(cls) -> bool:
        return cls._debug

    @classmethod
    def get_defaults(cls) -> DefaultParams:
        return DefaultParams(debug=cls._debug, logger=cls._logger)

    @classmethod
    def set_defaults(cls, debug: bool, logger: Logger) -> None:
        cls._debug = debug
        cls._logger = logger
