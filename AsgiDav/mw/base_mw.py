"""
Abstract base middleware class (optional use).
"""

from abc import ABC, abstractmethod

from AsgiDav.util import NO_DEFAULT, get_dict_value

__docformat__ = "reStructuredText"


class BaseMiddleware(ABC):
    """Abstract base middleware class (optional).

    Note: this is a convenience class, that *may* be used to implement WsgiDAV
    middlewares. However it is not a reqiuement: any object that implements
    the WSGI specification can be added to the stack.

    Derived classes in WsgiDAV include::

        AsgiDav.mw.debug_filter.WsgiDavDebugFilter
        AsgiDav.mw.error_printer.ErrorPrinter
        AsgiDav.mw.http_authenticator.HTTPAuthenticator
        AsgiDav.mw.request_resolver.RequestResolver
    """

    def __init__(self, app, next_app, config):
        self.app = app
        self.next_app = next_app
        self.config = config
        self.verbose = config.get("verbose", 3)

    @abstractmethod
    def __call__(self, scope, receive, send):
        raise NotImplementedError

    def __repr__(self):
        return f"{self.__module__}.{self.__class__.__name__}"

    def is_disabled(self):
        """Optionally return True to skip this module on startup."""
        return False

    def get_config(self, key_path: str, default=NO_DEFAULT):
        """Optionally return True to skip this module on startup."""
        res = get_dict_value(self.config, key_path, default)
        return res
