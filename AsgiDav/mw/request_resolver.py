# (c) 2009-2024 Martin Wendt and contributors; see WsgiDAV https://github.com/mar10/wsgidav
# Original PyFileServer (c) 2005 Ho Chun Wei.
# Licensed under the MIT license:
# http://www.opensource.org/licenses/mit-license.php
"""
WSGI middleware that finds the registered mapped DAV-Provider, creates a new
RequestServer instance, and dispatches the request.

.. warning::
   The following documentation was taken over from PyFileServer and is outdated.

WsgiDAV file sharing
--------------------

WsgiDAV allows the user to specify in wsgidav.conf a number of
realms, and a number of users for each realm.

Realms
   Each realm corresponds to a filestructure on disk to be stored,
   for example::

      addShare('pubshare','/home/public/share')

   would allow the users to access using WebDAV the directory/file
   structure at /home/public/share from the url
   http://<servername:port>/<approot>/pubshare

   The realm name is set as '/pubshare'

   e.g. /home/public/share/WsgiDAV/LICENSE becomes accessible as
   http://<servername:port>/<approot>/pubshare/WsgiDAV/LICENSE

Users
   A number of user_name/password pairs can be set for each realm::

      adduser('pubshare', 'user_name', 'password', 'description/unused')

   would add a user_name/password pair to realm /pubshare.

Note: if developers wish to maintain a separate users database, you can
write your own domain controller for the HTTPAuthenticator. See
http_authenticator.py and domain_controller.py for more details.


Request Resolver
----------------

WSGI middleware for resolving Realm and Paths for the WsgiDAV
application.

Usage::
   It *must* be configured as the last item on `middleware_stack` list.

   from AsgiDav.mw.request_resolver import RequestResolver
   config = {
        ...,
        'middleware_stack': [
            ...,
            RequestResolver,
        ],
    }

The RequestResolver resolves the requested URL to the following values
placed in the environ dictionary. First it resolves the corresponding
realm::

   url: http://<servername:port>/<approot>/pubshare/WsgiDAV/LICENSE
   environ['wsgidav.mappedrealm'] = /pubshare

Based on the configuration given, the resource abstraction layer for the
realm is determined. if no configured abstraction layer is found, the
default abstraction layer fileabstractionlayer.FilesystemAbstractionLayer()
is used::

   environ['wsgidav.resourceAL'] = fileabstractionlayer.MyOwnFilesystemAbstractionLayer()

The path identifiers for the requested url are then resolved using the
resource abstraction layer::

   environ['wsgidav.mappedpath'] = /home/public/share/WsgiDAV/LICENSE
   environ['wsgidav.mappedURI'] = /pubshare/WsgiDAV/LICENSE

in this case, FilesystemAbstractionLayer resolves any relative paths
to its canonical absolute path

The RequestResolver also resolves any value in the Destination request
header, if present, to::

   Destination: http://<servername:port>/<approot>/pubshare/WsgiDAV/LICENSE-dest
   environ['wsgidav.destrealm'] = /pubshare
   environ['wsgidav.destpath'] = /home/public/share/WsgiDAV/LICENSE-dest
   environ['wsgidav.destURI'] = /pubshare/WsgiDAV/LICENSE
   environ['wsgidav.destresourceAL'] = fileabstractionlayer.MyOwnFilesystemAbstractionLayer()

"""

from AsgiDav import util
from AsgiDav.base_class import HTTPScope
from AsgiDav.dav_error import HTTP_NOT_FOUND, DAVError
from AsgiDav.mw.base_mw import BaseMiddleware
from AsgiDav.request_server import RequestServer

__docformat__ = "reStructuredText"

_logger = util.get_module_logger(__name__)

# NOTE (Martin Wendt, 2009-05):
# The following remarks were made by Ian Bicking when reviewing PyFileServer in 2005.
# I leave them here after my refactoring for reference.
#
# Remarks:
# @@: If this were just generalized URL mapping, you'd map it like:
#    Incoming:
#        SCRIPT_NAME=<approot>; PATH_INFO=/pubshare/PyFileServer/LICENSE
#    After transforamtion:
#        SCRIPT_NAME=<approot>/pubshare; PATH_INFO=/PyFileServer/LICENSE
#    Then you dispatch to the application that serves '/home/public/share/'
#
#    This uses SCRIPT_NAME and PATH_INFO exactly how they are intended to be
#    used -- they give context about where you are (SCRIPT_NAME) and what you
#    still have to handle (PATH_INFO)
#
#    An example of an dispatcher that does this is paste.urlmap, and you use it
#    like:
#
#      urlmap = paste.urlmap.URLMap()
#      # urlmap is a WSGI application
#      urlmap['/pubshare'] = PyFileServerForPath('/home/public/share')
#
#    Now, that requires that you have a server that is easily
#    instantiated, but that's kind of a separate concern -- what you
#    really want is to do more general configuration at another level.  E.g.,
#    you might have::
#
#      app = config(urlmap, config_file)
#
#    Which adds the configuration from that file to the request, and
#    PyFileServerForPath then fetches that configuration.  paste.deploy
#    has another way of doing that at instantiation-time; either way
#    though you want to inherit configuration you can still use more general
#    dispatching.
#
#    Incidentally some WebDAV servers do redirection based on the user
#    agent (Zope most notably).  This is because of how WebDAV reuses
#    GET in an obnxious way, so that if you want to use WebDAV on pages
#    that also include dynamic content you have to mount the whole
#    thing at another point in the URL space, so you can GET the
#    content without rendering the dynamic parts.  I don't actually
#    like using user agents -- I'd rather mount the same resources at
#    two different URLs -- but it's just an example of another kind of
#    dispatching that can be done at a higher level.
#

# ========================================================================
# RequestResolver
# ========================================================================


class RequestResolver(BaseMiddleware):
    def __init__(self, app, next_app, config):
        super().__init__(app, next_app, config)

    async def __call__(self, scope: HTTPScope, receive, send):
        path = scope.path

        # We want to answer OPTIONS(*), even if no handler was registered for
        # the top-level realm (e.g. required to map drive letters).
        provider = scope.asgidav.provider
        config = scope.asgidav.config
        hotfixes = util.get_dict_value(config, "hotfixes", as_dict=True)
        is_asterisk_options = scope.method == "OPTIONS" and path == "*"

        if path == "/":
            # Hotfix for WinXP / Vista: accept '/' for a '*'
            treat_as_asterisk = hotfixes.get("treat_root_options_as_asterisk")
            if treat_as_asterisk:
                is_asterisk_options = True
            else:
                _logger.info("Got OPTIONS '/' request")

        if is_asterisk_options:
            # Answer HTTP 'OPTIONS' method on server-level.
            # From RFC 2616:
            # If the Request-URI is an asterisk ("*"), the OPTIONS request is
            # intended to apply to the server in general rather than to a specific
            # resource. Since a server's communication options typically depend on
            # the resource, the "*" request is only useful as a "ping" or "no-op"
            # type of method; it does nothing beyond allowing the client to test the
            # capabilities of the server. For example, this can be used to test a
            # proxy for HTTP/1.1 compliance (or lack thereof).

            dav_compliance_level = "1,2"

            if (
                provider is None
                or provider.is_readonly()
                or provider.lock_manager is None
            ):
                dav_compliance_level = "1"

            headers = [
                ("Content-Type", "text/html; charset=utf-8"),
                ("Content-Length", "0"),
                ("DAV", dav_compliance_level),
                ("Date", util.get_rfc1123_time()),
            ]

            if scope.asgidav.config.get("add_header_MS_Author_Via", False):
                headers.append(("MS-Author-Via", "DAV"))

            await util.send_start_response(send, 200, headers)
            await util.send_body_response(send, b"")

            return

        if provider is None:
            raise DAVError(
                HTTP_NOT_FOUND, f"Could not find resource provider for {path!r}"
            )

        # Let the appropriate resource provider for the realm handle the
        # request
        app = RequestServer(provider)

        await app(scope, receive, send)
