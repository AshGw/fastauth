from logging import Logger
from typing import NamedTuple
from fastauth.log import logger as flogger


class DefaultPararms(NamedTuple):
    debug: bool
    logger: Logger


class Defaults:
    _logger: Logger = flogger
    _debug: bool = True

    def get_defaults(self) -> DefaultPararms:
        return DefaultPararms(debug=self._debug, logger=self._logger)

    def set_defaults(self, debug: bool, logger: Logger) -> None:
        self._debug = debug
        self._logger = logger
