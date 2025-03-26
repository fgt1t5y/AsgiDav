# (c) 2009-2024 Martin Wendt and contributors; see WsgiDAV https://github.com/mar10/wsgidav
# Licensed under the MIT license:
# http://www.opensource.org/licenses/mit-license.php
"""
WSGI middleware used for CORS support (optional).

Respond to CORS preflight OPTIONS request and inject CORS headers.
"""

from AsgiDav import util
from AsgiDav.mw.base_mw import BaseMiddleware

__docformat__ = "reStructuredText"

_logger = util.get_module_logger(__name__)


class Logging(BaseMiddleware):
    def __init__(self, wsgidav_app, next_app, config):
        super().__init__(wsgidav_app, next_app, config)

    def __call__(self, environ, start_response):
        def wrapped_start_response(status, headers, exc_info=None):
            start_response(status, headers, exc_info)

        return self.next_app(environ, wrapped_start_response)
