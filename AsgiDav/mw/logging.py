# (c) 2009-2024 Martin Wendt and contributors; see WsgiDAV https://github.com/mar10/wsgidav
# Licensed under the MIT license:
# http://www.opensource.org/licenses/mit-license.php
"""
WSGI middleware used for CORS support (optional).

Respond to CORS preflight OPTIONS request and inject CORS headers.
"""

from AsgiDav import util
from AsgiDav.base_class import HTTPScope
from AsgiDav.mw.base_mw import BaseMiddleware

__docformat__ = "reStructuredText"

_logger = util.get_module_logger(__name__)


class Logging(BaseMiddleware):
    def __init__(self, app, next_app, config):
        super().__init__(app, next_app, config)

    def is_disabled(self):
        """Optionally return True to skip this module on startup."""
        return False

    async def __call__(self, scope: HTTPScope, receive, send):
        await self.next_app(scope, receive, send)
