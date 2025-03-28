# (c) 2009-2024 Martin Wendt and contributors; see WsgiDAV https://github.com/mar10/wsgidav
# Original PyFileServer (c) 2005 Ho Chun Wei.
# Licensed under the MIT license:
# http://www.opensource.org/licenses/mit-license.php
"""
WSGI middleware to catch application thrown DAVErrors and return proper
responses.
"""

import traceback

from AsgiDav import util
from AsgiDav.base_class import HTTPScope
from AsgiDav.dav_error import (
    HTTP_INTERNAL_ERROR,
    HTTP_NO_CONTENT,
    HTTP_NOT_MODIFIED,
    DAVError,
    as_DAVError,
    get_http_status_code,
)
from AsgiDav.mw.base_mw import BaseMiddleware

__docformat__ = "reStructuredText"

_logger = util.get_module_logger(__name__)


# ========================================================================
# ErrorPrinter
# ========================================================================
class ErrorPrinter(BaseMiddleware):
    def __init__(self, wsgidav_app, next_app, config):
        super().__init__(wsgidav_app, next_app, config)
        self.err_config = util.get_dict_value(config, "error_printer", as_dict=True)

    def is_disabled(self):
        return self.err_config.get("enable") is False

    async def __call__(self, scope: HTTPScope, receive, send):
        # Intercept start_response
        try:
            try:
                # request_server app may be a generator (for example the GET handler)
                # So we must iterate - not return self.next_app(..)!
                # Otherwise the we could not catch exceptions here.
                await self.next_app(scope, receive, send)
            except DAVError:
                raise  # Deliberately generated or already converted
            except Exception as e:
                # Caught a non-DAVError
                # Catch all exceptions to return as 500 Internal Error
                _logger.error(f"{traceback.format_exc(10)}")
                raise as_DAVError(e) from None
        except DAVError as e:
            _logger.debug(f"Caught {e}")

            status = get_http_status_code(e)

            # Dump internal errors to console
            if e.value == HTTP_INTERNAL_ERROR:
                tb = traceback.format_exc(10)
                _logger.error(f"Caught HTTPRequestException(HTTP_INTERNAL_ERROR)\n{tb}")
                # traceback.print_exc(10, environ.get("wsgi.errors") or sys.stdout)
                _logger.error(f"e.src_exception:\n{e.src_exception}")
            elif e.value in (HTTP_NOT_MODIFIED, HTTP_NO_CONTENT):
                await util.send_start_response(
                    send,
                    status,
                    [("Content-Length", "0"), ("Date", util.get_rfc1123_time())],
                )
                await util.send_body_response(send, b"")

                return

            # If exception has pre-/post-condition: return as XML response,
            # else return as HTML
            content_type, body = e.get_response_page()
            headers = e.add_headers or []
            # TODO: provide exc_info=sys.exc_info()?
            await util.send_start_response(
                send,
                status,
                [
                    ("Content-Type", content_type),
                    ("Content-Length", str(len(body))),
                    ("Date", util.get_rfc1123_time()),
                ]
                + headers,
            )
            await util.send_body_response(send, body)
