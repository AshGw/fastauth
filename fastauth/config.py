from __future__ import annotations
from logging import Logger
from typing import NamedTuple, ClassVar
from fastauth.log import logger as flogger
from fastauth.frameworks import Framework


class FastAuthConfig:
    framework: ClassVar[Framework]
    passed_csrf_validation: ClassVar[bool] = True
    logger: ClassVar[Logger] = flogger
    debug: ClassVar[bool] = True

    @classmethod
    def get_defaults(cls) -> _DefaultVars:
        return _DefaultVars(framework=cls.framework, debug=cls.debug, logger=cls.logger)

    @classmethod
    def set_defaults(cls, framework: Framework, debug: bool, logger: Logger) -> None:
        cls.framework = framework
        cls.debug = debug
        cls.logger = logger


class _DefaultVars(NamedTuple):
    framework: Framework
    debug: bool
    logger: Logger
