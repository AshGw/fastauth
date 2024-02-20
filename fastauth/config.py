from __future__ import annotations
from logging import Logger
from typing import NamedTuple, ClassVar
from fastauth.log import logger as flogger
from fastauth.frameworks import Framework


class FastAuthConfig:
    framework: Framework
    logger: ClassVar[Logger] = flogger
    debug: ClassVar[bool] = True

    @classmethod
    def get_defaults(cls) -> _DefaultAttrs:
        return _DefaultAttrs(
            framework=cls.framework, debug=cls.debug, logger=cls.logger
        )

    @classmethod
    def set_defaults(cls, framework: Framework, debug: bool, logger: Logger) -> None:
        cls.framework = framework
        cls.debug = debug
        cls.logger = logger


class _DefaultAttrs(NamedTuple):
    framework: Framework
    debug: bool
    logger: Logger
