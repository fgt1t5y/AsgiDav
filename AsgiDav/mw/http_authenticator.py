# (c) 2009-2024 Martin Wendt and contributors; see WsgiDAV https://github.com/mar10/wsgidav
# Original PyFileServer (c) 2005 Ho Chun Wei.
# Licensed under the MIT license:
# http://www.opensource.org/licenses/mit-license.php
"""
WSGI middleware for HTTP basic and digest authentication.

Usage::

   from http_authenticator import HTTPAuthenticator

   WSGIApp = HTTPAuthenticator(ProtectedWSGIApp, domain_controller, accept_basic,
                               accept_digest, default_to_digest)

   where:
     ProtectedWSGIApp is the application requiring authenticated access

     domain_controller is a domain controller object meeting specific
     requirements (below)

     accept_basic is a boolean indicating whether to accept requests using
     the basic authentication scheme (default = True)

     accept_digest is a boolean indicating whether to accept requests using
     the digest authentication scheme (default = True)

     default_to_digest is a boolean. if True, an unauthenticated request will
     be sent a digest authentication required response, else the unauthenticated
     request will be sent a basic authentication required response
     (default = True)

The HTTPAuthenticator will put the following authenticated information in the
environ dictionary::

   environ["wsgidav.auth.realm"] = realm name
   environ["wsgidav.auth.user_name"] = user_name
   environ["wsgidav.auth.roles"] = <tuple> (optional)
   environ["wsgidav.auth.permissions"] = <tuple> (optional)


**Domain Controllers**

The HTTP basic and digest authentication schemes are based on the following
concept:

Each requested relative URI can be resolved to a realm for authentication,
for example:
/fac_eng/courses/ee5903/timetable.pdf -> might resolve to realm 'Engineering General'
/fac_eng/examsolns/ee5903/thisyearssolns.pdf -> might resolve to realm 'Engineering Lecturers'
/med_sci/courses/m500/surgery.htm -> might resolve to realm 'Medical Sciences General'
and each realm would have a set of user_name and password pairs that would
allow access to the resource.

A domain controller provides this information to the HTTPAuthenticator.
This allows developers to write their own domain controllers, that might,
for example, interface with their own user database.

for simple applications, a SimpleDomainController is provided that will take
in a single realm name (for display) and a single dictionary of user_name (key)
and password (value) string pairs

Usage::

   from AsgiDav.dc.simple_dc import SimpleDomainController
   users = dict(({'John Smith': 'YouNeverGuessMe', 'Dan Brown': 'DontGuessMeEither'})
   realm = 'Sample Realm'
   domain_controller = SimpleDomainController(users, realm)


Domain Controllers must provide the methods as described in
``wsgidav.interfaces.domaincontrollerinterface`` (interface_)

.. _interface : interfaces/domaincontrollerinterface.py

The environ variable here is the WSGI 'environ' dictionary. It is passed to
all methods of the domain controller as a means for developers to pass information
from previous middleware or server config (if required).
"""

import base64
import inspect
import random
import re
import time
from hashlib import md5
from textwrap import dedent

from AsgiDav import util
from AsgiDav.base_class import HTTPScope
from AsgiDav.dav_error import HTTP_NOT_FOUND, DAVError
from AsgiDav.dc.simple_dc import SimpleDomainController
from AsgiDav.mw.base_mw import BaseMiddleware
from AsgiDav.util import calc_base64, calc_hexdigest, dynamic_import_class

__docformat__ = "reStructuredText"

_logger = util.get_module_logger(__name__)


def make_domain_controller(wsgidav_app, config):
    auth_conf = util.get_dict_value(config, "http_authenticator", as_dict=True)
    dc = auth_conf.get("domain_controller")
    org_dc = dc
    if dc is True or not dc:
        # True or null:
        dc = SimpleDomainController
    elif util.is_basestring(dc):
        # If a plain string is passed, try to import it as class
        dc = dynamic_import_class(dc)

    if inspect.isclass(dc):
        # If a class is passed, instantiate that
        dc = dc(wsgidav_app, config)
    else:
        raise RuntimeError(f"Could not resolve domain controller class (got {org_dc})")
    # print("make_domain_controller", dc)
    return dc


# ========================================================================
# HTTPAuthenticator
# ========================================================================
class HTTPAuthenticator(BaseMiddleware):
    """WSGI Middleware for basic and digest authentication."""

    error_message_401 = dedent(
        """\
        <html>
            <head><title>401 Access not authorized</title></head>
            <body>
                <h1>401 Access not authorized</h1>
            </body>
        </html>
    """
    )

    def __init__(self, app, next_app, config):
        super().__init__(app, next_app, config)

        self._verbose = config.get("verbose", 3)
        self.config = config
        dc = make_domain_controller(app, config)
        self.domain_controller = dc
        hotfixes = util.get_dict_value(config, "hotfixes", as_dict=True)
        # HOT FIX for Windows XP (Microsoft-WebDAV-MiniRedir/5.1.2600):
        # When accessing a share '/dav/', XP sometimes sends digests for '/'.
        # With this fix turned on, we allow '/' digests, when a matching '/dav' account
        # is present.
        self.winxp_accept_root_share_login = hotfixes.get(
            "winxp_accept_root_share_login", False
        )
        # HOTFIX for Windows
        # MW 2013-12-31: DON'T set this (will MS office to use anonymous always in
        # some scenarios)
        self.win_accept_anonymous_options = hotfixes.get(
            "win_accept_anonymous_options", False
        )

        auth_conf = util.get_dict_value(config, "http_authenticator", as_dict=True)

        self.accept_basic = auth_conf.get("accept_basic", True)
        self.accept_digest = auth_conf.get("accept_digest", True)
        self.default_to_digest = auth_conf.get("default_to_digest", True)
        self.trusted_auth_header = auth_conf.get("trusted_auth_header", None)

        if not dc.supports_http_digest_auth() and (
            self.accept_digest or self.default_to_digest or not self.accept_basic
        ):
            raise RuntimeError(
                f"{dc.__class__.__name__} does not support digest authentication.\n"
                "Set accept_basic=True, accept_digest=False, default_to_digest=False"
            )

        self._nonce_dict = dict([])

        self._header_parser = re.compile(r"([\w]+)=([^,]*),")
        # Note: extra parser to handle digest auth requests from certain
        # clients, that leave commas un-encoded to interfere with the above.
        self._header_fix_parser = re.compile(r'([\w]+)=("[^"]*,[^"]*"),')
        self._header_method = re.compile(r"^([\w]+)")

    def get_domain_controller(self):
        return self.domain_controller

    def allow_anonymous_access(self, share):
        return not self.domain_controller.require_authentication(share, None)

    async def __call__(self, scope: HTTPScope, receive, send):
        realm = self.domain_controller.get_domain_realm(scope.path, scope)
        query_string = scope.query_string.decode()

        scope.asgidav.auth.realm = realm
        scope.asgidav.auth.user_name = ""
        # The domain controller MAY set those values depending on user's
        # authorization:
        scope.asgidav.auth.roles = None
        scope.asgidav.auth.permissions = None

        force_logout = False
        if "logout" in query_string:
            force_logout = True
            _logger.warning("Force logout")

        force_allow = False
        if self.win_accept_anonymous_options and scope.method == "OPTIONS":
            _logger.warning("No authorization required for OPTIONS method")
            force_allow = True

        if force_allow or not self.domain_controller.require_authentication(
            realm, scope
        ):
            # No authentication needed
            # _logger.debug("No authorization required for realm {!r}".format(realm))
            # environ["wsgidav.auth.realm"] = realm
            # environ["wsgidav.auth.user_name"] = ""
            await self.next_app(scope, receive, send)

            return

        if self.trusted_auth_header and scope.headers.get(self.trusted_auth_header):
            # accept a user_name that was injected by a trusted upstream server
            _logger.debug(
                f"Accept trusted user_name {self.trusted_auth_header}={scope.headers.get(self.trusted_auth_header)!r}for realm {realm!r}"
            )
            # environ["wsgidav.auth.realm"] = realm
            scope.asgidav.auth.user_name = scope.headers.get(self.trusted_auth_header)

            await self.next_app(scope, receive, send)

            return

        if scope.HTTP_AUTHORIZATION and not force_logout:
            auth_header = scope.HTTP_AUTHORIZATION
            auth_match = self._header_method.search(auth_header)
            auth_method = "None"
            if auth_match:
                auth_method = auth_match.group(1).lower()

            if auth_method == "digest" and self.accept_digest:
                await self.handle_digest_auth_request(scope, receive, send)

                return
            elif auth_method == "digest" and self.accept_basic:
                await self.send_basic_auth_response(scope, receive, send)

                return
            elif auth_method == "basic" and self.accept_basic:
                await self.handle_basic_auth_request(scope, receive, send)

                return
            # The requested auth method is not supported.
            elif self.default_to_digest and self.accept_digest:
                await self.send_digest_auth_response(scope, receive, send)

                return
            elif self.accept_basic:
                await self.send_basic_auth_response(scope, receive, send)

                return

            _logger.warning(
                f"HTTPAuthenticator: respond with 400 Bad request; Auth-Method: {auth_method}"
            )

            await util.send_start_response(
                send, 400, [("Content-Length", "0"), ("Date", util.get_rfc1123_time())]
            )
            await util.send_body_response(send, b"")

            return

        if self.default_to_digest:
            await self.send_digest_auth_response(scope, receive, send)

            return

        await self.send_basic_auth_response(scope, receive, send)

    async def send_basic_auth_response(self, scope: HTTPScope, receive, send):
        realm = self.domain_controller.get_domain_realm(scope.path, scope)
        _logger.debug(f"401 Not Authorized for realm {realm!r} (basic)")
        wwwauthheaders = f'Basic realm="{realm}"'

        body = util.to_bytes(self.error_message_401)

        await util.send_start_response(
            send,
            401,
            [
                ("WWW-Authenticate", wwwauthheaders),
                ("Content-Type", "text/html; charset=utf-8"),
                ("Content-Length", str(len(body))),
                ("Date", util.get_rfc1123_time()),
            ],
        )
        await util.send_body_response(send, body)

    async def handle_basic_auth_request(self, scope: HTTPScope, receive, send):
        realm = self.domain_controller.get_domain_realm(scope.path, scope)
        auth_header = scope.HTTP_AUTHORIZATION
        auth_value = ""
        try:
            auth_value = auth_header[len("Basic ") :].strip()
        except Exception:
            auth_value = ""

        auth_value = base64.decodebytes(util.to_bytes(auth_value))
        auth_value = util.to_str(auth_value)
        user_name, password = auth_value.split(":", 1)

        if self.domain_controller.basic_auth_user(realm, user_name, password, scope):
            scope.asgidav.auth.realm = realm
            scope.asgidav.auth.user_name = user_name

            await self.next_app(scope, receive, send)

            return

        _logger.warning(
            f"Authentication (basic) failed for user {user_name!r}, realm {realm!r}."
        )

        await self.send_basic_auth_response(scope, receive, send)

    async def send_digest_auth_response(self, scope: HTTPScope, receive, send):
        realm = self.domain_controller.get_domain_realm(scope.path, scope)
        random.seed()
        serverkey = hex(random.getrandbits(32))[2:]
        etagkey = calc_hexdigest(scope.path)
        timekey = str(time.time())
        nonce_source = timekey + calc_hexdigest(
            timekey + ":" + etagkey + ":" + serverkey
        )
        nonce = calc_base64(nonce_source)
        wwwauthheaders = (
            f'Digest realm="{realm}", nonce="{nonce}", algorithm=MD5, qop="auth"'
        )

        _logger.debug(
            f"401 Not Authorized for realm {realm!r} (digest): {wwwauthheaders}"
        )

        body = util.to_bytes(self.error_message_401)

        await util.send_start_response(
            send,
            401,
            [
                ("WWW-Authenticate", wwwauthheaders),
                ("Content-Type", "text/html; charset=utf-8"),
                ("Content-Length", str(len(body))),
                ("Date", util.get_rfc1123_time()),
            ],
        )
        await util.send_body_response(send, body)

    async def handle_digest_auth_request(self, scope: HTTPScope, receive, send):
        realm = self.domain_controller.get_domain_realm(scope.path, scope)

        if not realm:
            raise DAVError(
                HTTP_NOT_FOUND,
                context_info=f"Could not resolve realm for {scope.path}",
            )

        is_invalid_req = False
        invalid_req_reasons = []

        auth_header_dict = {}
        auth_headers = scope.HTTP_AUTHORIZATION + ","
        if not auth_headers.lower().strip().startswith("digest"):
            is_invalid_req = True
            invalid_req_reasons.append(
                f"HTTP_AUTHORIZATION must start with 'digest': {auth_headers}"
            )
        # Hotfix for Windows file manager and OSX Finder:
        # Some clients don't urlencode paths in auth header, so uri value may
        # contain commas, which break the usual regex headerparser. Example:
        # Digest user_name="user",realm="/",uri="a,b.txt",nc=00000001, ...
        # -> [..., ('uri', '"a'), ('nc', '00000001'), ...]
        # Override any such values with carefully extracted ones.
        auth_header_list = self._header_parser.findall(auth_headers)
        auth_header_fixlist = self._header_fix_parser.findall(auth_headers)
        if auth_header_fixlist:
            _logger.info(
                f"Fixing auth_header comma-parsing: extend {auth_header_list} with {auth_header_fixlist}"
            )
            auth_header_list += auth_header_fixlist

        for auth_header in auth_header_list:
            auth_header_key = auth_header[0]
            auth_header_value = auth_header[1].strip().strip('"')
            auth_header_dict[auth_header_key] = auth_header_value

        req_username = None
        if "username" in auth_header_dict:
            req_username = auth_header_dict["username"]
            if not req_username:
                is_invalid_req = True
                invalid_req_reasons.append(f"`username` is empty: {req_username!r}")
            elif r"\\" in req_username:
                # Hotfix for Windows XP:
                #   net use W: http://127.0.0.1/dav /USER:DOMAIN\tester tester
                # will send the name with double backslashes ('DOMAIN\\tester')
                # but send the digest for the simple name ('DOMAIN\tester').
                req_username_org = req_username
                req_username = req_username.replace("\\\\", "\\")
                _logger.info(
                    f"Fixing Windows name with double backslash: {req_username_org!r} --> {req_username!r}"
                )

            # pre_check = self.domain_controller.is_realm_user(
            #     realm, req_username, environ
            # )
            # if pre_check is False:
            #     is_invalid_req = True
            #     invalid_req_reasons.append(
            #         "Not a realm-user: {!r}/{!r}".format(realm, req_username)
            #     )
        else:
            is_invalid_req = True
            invalid_req_reasons.append("Missing 'username' in headers")

        # TODO: Chun added this comments, but code was commented out:
        # Do not do realm checking - a hotfix for WinXP using some other realm's
        # auth details for this realm - if user/password match
        if "realm" in auth_header_dict:
            if auth_header_dict["realm"].upper() != realm.upper():
                if (
                    self.winxp_accept_root_share_login
                    and auth_header_dict["realm"] == "/"
                ):
                    # Hotfix: also accept '/'
                    _logger.info("winxp_accept_root_share_login")
                else:
                    is_invalid_req = True
                    invalid_req_reasons.append(f"Realm mismatch: {realm!r}")

        if "algorithm" in auth_header_dict:
            if auth_header_dict["algorithm"].upper() != "MD5":
                is_invalid_req = True  # only MD5 supported
                invalid_req_reasons.append("Unsupported 'algorithm' in headers")

        req_uri = auth_header_dict.get("uri")

        if "nonce" in auth_header_dict:
            req_nonce = auth_header_dict["nonce"]
        else:
            is_invalid_req = True
            invalid_req_reasons.append("Expected 'nonce' in headers")

        req_has_qop = False
        if "qop" in auth_header_dict:
            req_has_qop = True
            req_qop = auth_header_dict["qop"]
            if req_qop.lower() != "auth":
                is_invalid_req = True  # only auth supported, auth-int not supported
                invalid_req_reasons.append("Expected 'qop' == 'auth'")
        else:
            req_qop = None

        if "cnonce" in auth_header_dict:
            req_cnonce = auth_header_dict["cnonce"]
        else:
            req_cnonce = None
            if req_has_qop:
                is_invalid_req = True
                invalid_req_reasons.append(
                    "Expected 'cnonce' in headers if qop is passed"
                )

        if "nc" in auth_header_dict:  # is read but nonce-count checking not implemented
            req_nc = auth_header_dict["nc"]
        else:
            req_nc = None
            if req_has_qop:
                is_invalid_req = True
                invalid_req_reasons.append("Expected 'nc' in headers if qop is passed")

        if "response" in auth_header_dict:
            req_response = auth_header_dict["response"]
        else:
            is_invalid_req = True
            invalid_req_reasons.append("Expected 'response' in headers")

        if not is_invalid_req:
            req_method = scope.method

            required_digest = self._compute_digest_response(
                realm,
                req_username,
                req_method,
                req_uri,
                req_nonce,
                req_cnonce,
                req_qop,
                req_nc,
                scope,
            )

            if not required_digest:
                # Rejected by domain controller
                is_invalid_req = True
                invalid_req_reasons.append(
                    f"Rejected by DC.digest_auth_user({realm!r}, {req_username!r})"
                )
            elif required_digest != req_response:
                warning_msg = f"_compute_digest_response({realm!r}, {req_username!r}, ...): {required_digest} != {req_response}"
                if self.winxp_accept_root_share_login and realm != "/":
                    # _logger.warning(warning_msg + " => trying '/' realm")
                    # Hotfix: also accept '/' digest
                    root_digest = self._compute_digest_response(
                        "/",
                        req_username,
                        req_method,
                        req_uri,
                        req_nonce,
                        req_cnonce,
                        req_qop,
                        req_nc,
                        scope,
                    )
                    if root_digest == req_response:
                        _logger.warning(
                            f"handle_digest_auth_request: HOTFIX: accepting '/' login for {realm!r}."
                        )
                    else:
                        is_invalid_req = True
                        invalid_req_reasons.append(
                            warning_msg + " (also tried '/' realm)"
                        )
                else:
                    is_invalid_req = True
                    invalid_req_reasons.append(warning_msg)
            else:
                # _logger.debug("digest succeeded for realm {!r}, user {!r}"
                #               .format(realm, req_username))
                pass

        if is_invalid_req:
            invalid_req_reasons.append(f"Headers:\n    {auth_header_dict}")
            if self._verbose >= 4:
                _logger.warning(
                    "Authentication (digest) failed for user {!r}, realm {!r}:\n  {}".format(
                        req_username, realm, "\n  ".join(invalid_req_reasons)
                    )
                )
            else:
                _logger.warning(
                    f"Authentication (digest) failed for user {req_username!r}, realm {realm!r}."
                )

            await self.send_digest_auth_response(scope, receive, send)

            return

        scope.asgidav.auth.realm = realm
        scope.asgidav.auth.user_name = req_username

        await self.next_app(scope, receive, send)

    def _compute_digest_response(
        self, realm, user_name, method, uri, nonce, cnonce, qop, nc, scope: HTTPScope
    ):
        """Computes digest hash.

        Calculation of the A1 (HA1) part is delegated to the dc interface method
        `digest_auth_user()`.

        Args:
            realm (str):
            user_name (str):
            method (str): WebDAV Request Method
            uri (str):
            nonce (str): server generated nonce value
            cnonce (str): client generated cnonce value
            qop (str): quality of protection
            nc (str) (number), nonce counter incremented by client
        Returns:
            MD5 hash string
            or False if user rejected by domain controller
        """

        def md5h(data):
            return md5(util.to_bytes(data)).hexdigest()

        def md5kd(secret, data):
            return md5h(secret + ":" + data)

        A1 = self.domain_controller.digest_auth_user(realm, user_name, scope)
        if not A1:
            return False

        A2 = method + ":" + uri

        if qop:
            res = md5kd(
                A1, nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + md5h(A2)
            )
        else:
            res = md5kd(A1, nonce + ":" + md5h(A2))

        return res
