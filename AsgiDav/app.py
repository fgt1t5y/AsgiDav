# (c) 2009-2024 Martin Wendt and contributors; see WsgiDAV https://github.com/mar10/wsgidav
# Original PyFileServer (c) 2005 Ho Chun Wei.
# Licensed under the MIT license:
# http://www.opensource.org/licenses/mit-license.php
r"""
::

     _      __         _ ___  ___ _   __
    | | /| / /__ ___  (_) _ \/ _ | | / /
    | |/ |/ (_-</ _ `/ / // / __ | |/ /
    |__/|__/___/\_, /_/____/_/ |_|___/
               /___/

WSGI container, that handles the HTTP requests. This object is passed to the
WSGI server and represents our WsgiDAV application to the outside.

On init:

    Use the configuration dictionary to initialize lock manager, property manager,
    domain controller.

    Create a dictionary of share-to-provider mappings.

    Initialize middleware objects and setup the WSGI application stack.

For every request:

    Find the registered DAV provider for the current request.

    Add or modify info in the WSGI ``scope``:

        scope["root_path"]
            Mount-point of the current share.
        scope["PATH_INFO"]
            Resource path, relative to the mount path.
        scope["wsgidav.provider"]
            DAVProvider object that is registered for handling the current
            request.
        scope["wsgidav.config"]
            Configuration dictionary.
        scope["wsgidav.verbose"]
            Debug level [0-3].

    Log the HTTP request, then pass the request to the first middleware.

    Note: The OPTIONS method for the '*' path is handled directly.

"""

import copy
import inspect
import platform
import sys
from urllib.parse import unquote

from AsgiDav import __version__, util
from AsgiDav.base_class import HTTPScope
from AsgiDav.dav_provider import DAVProvider
from AsgiDav.default_conf import DEFAULT_CONFIG
from AsgiDav.fs_dav_provider import FilesystemProvider
from AsgiDav.lock_man.lock_manager import LockManager
from AsgiDav.lock_man.lock_storage import LockStorageDict
from AsgiDav.mw.base_mw import BaseMiddleware
from AsgiDav.mw.http_authenticator import HTTPAuthenticator
from AsgiDav.prop_man.property_manager import PropertyManager
from AsgiDav.request_server import RequestServer

__docformat__ = "reStructuredText"

_logger = util.get_module_logger(__name__)


#: Minimal Python version that is supported by WsgiDAV
MIN_PYTHON_VERSION_INFO = (3, 9)

# check_python_version(MIN_PYTHON_VERSION_INFO)


class WsgiDAVApp:
    def __init__(self, config):
        self.config = copy.deepcopy(DEFAULT_CONFIG)
        util.deep_update(self.config, config)
        config = self.config

        if config["logging"].get("enable") is not False:
            util.init_logging(config)
        self.logger = _logger

        # Evaluate configuration and set defaults
        expand = {"${application}": self}

        errors = []

        mandatory_fields = ("provider_mapping",)
        for field in mandatory_fields:
            if field not in config:
                errors.append(f"Missing required option {field!r}.")

        deprecated_fields = {
            "acceptbasic": "http_authenticator.accept_basic",
            "acceptdigest": "http_authenticator.accept_digest",
            "accept_put_without_content_length": "(removed)",
            "catchall": "error_printer.catch_all",
            "debug_litmus": "logging.debug_litmus",
            "debug_methods": "logging.debug_methods",
            "defaultdigest": "http_authenticator.default_to_digest",
            "dir_browser.app_class": "middleware_stack",
            "dir_browser.ms_mount": "(removed)",
            "dir_browser.ms_sharepoint_plugin": "dir_browser.ms_sharepoint_support",
            "dir_browser.ms_sharepoint_url": "dir_browser.ms_sharepoint_support",
            "domain_controller": "http_authenticator.domain_controller",
            "domaincontroller": "http_authenticator.domain_controller",
            "emulate_win32_lastmod": "hotfixes.emulate_win32_lastmod",
            "enable_loggers": "logging.enable_loggers",
            "error_printer.catch_all": "(removed)",
            "http_authenticator.preset_domain": "nt_dc.preset_domain",
            "http_authenticator.preset_server": "nt_dc.preset_server",
            "locksmanager": "lock_manager",
            "lock_manager": "lock_storage",
            "logger_date_format": "logging.logger_date_format",
            "logger_format": "logging.logger_format",
            "logging.verbose": "verbose",  # prevent a likely mistake
            "mutableLiveProps": "mutable_live_props",
            "propsmanager": "property_manager",
            "re_encode_path_info": "hotfixes.re_encode_path_info",
            "response_headers": "(see Cors middleware)",
            "trusted_auth_header": "http_authenticator.trusted_auth_header",
            "unquote_path_info": "hotfixes.unquote_path_info",
            "user_mapping": "simple_dc.user_mapping",
            # "dir_browser.enable": "middleware_stack",
        }

        for old, new in deprecated_fields.items():
            if "." in old:
                k, v = old.split(".", 1)
                d = config.get(k, {})
            else:
                d, v = config, old

            if d and v in d:
                errors.append(f"Deprecated option {old!r}: use {new!r} instead.")

        if errors:
            raise ValueError("Invalid configuration:\n  - " + "\n  - ".join(errors))

        self.verbose: int = config.get("verbose", 3)

        hotfixes: dict = util.get_dict_value(config, "hotfixes", as_dict=True)

        self.re_encode_path_info: bool = hotfixes.get("re_encode_path_info", True)
        if type(self.re_encode_path_info) is not bool:
            raise ValueError("re_encode_path_info must be bool (or omitted)")
        self.unquote_path_info: bool = hotfixes.get("unquote_path_info", False)

        lock_storage = config.get("lock_storage")

        if lock_storage is True:
            lock_storage = LockStorageDict()
        elif isinstance(lock_storage, (str, dict)):
            lock_storage = util.dynamic_instantiate_class_from_opts(
                lock_storage, expand=expand
            )

        if not lock_storage:
            # Normalize False, 0 to None
            self.lock_manager = None
        else:
            if not hasattr(lock_storage, "refresh"):
                raise ValueError(f"Invalid lock_storage: {lock_storage!r}")
            self.lock_manager = LockManager(lock_storage)

        prop_manager = config.get("property_manager")
        if prop_manager is True:
            prop_manager = PropertyManager()
        elif isinstance(prop_manager, (str, dict)):
            prop_manager = util.dynamic_instantiate_class_from_opts(
                prop_manager, expand=expand
            )

        if not prop_manager:
            # Normalize False, 0 to None
            self.prop_manager = None
        else:
            self.prop_manager = prop_manager

        # If mount path is configured, it must start with "/" (but no trailing slash)
        mount_path = config.get("mount_path")
        if mount_path:
            if not mount_path.startswith("/") or mount_path.endswith("/"):
                raise ValueError(
                    f"If a mount_path is set, it must start (but not end) with '/': {mount_path!r}."
                )
        else:
            mount_path = ""
        self.mount_path = mount_path

        auth_conf = util.get_dict_value(config, "http_authenticator", as_dict=True)

        # Instantiate DAV resource provider objects for every share.
        # provider_mapping may contain the args that are passed to a
        # `FilesystemProvider` instance:
        #     <share_path>: <folder_path>
        # or
        #     <share_path>: { "root": <folder_path>, "readonly": True }
        # or contain a complete new instance:
        #     <share_path>: <DAVProvider Instance>

        provider_mapping = self.config["provider_mapping"]

        self.provider_map = {}
        self.sorted_share_list = []
        for share, provider in provider_mapping.items():
            self.add_provider(share, provider)

        self.http_authenticator = None
        domain_controller = None

        # Define WSGI application stack
        middleware_stack = config.get("middleware_stack", [])
        mw_list = []

        # This is the 'outer' application, i.e. the WSGI application object that
        # is eventually called by the server.
        self.application = self

        # The `middleware_stack` is configured such that the first app in the
        # list should be called first. Since every app wraps its predecessor, we
        # iterate in reverse order:
        for mw in reversed(middleware_stack):
            # The middleware stack configuration may contain plain strings, dicts,
            # classes, or objects
            app = None
            if util.is_basestring(mw):
                # If a plain string is passed, try to import it, assuming
                # `BaseMiddleware` signature
                app_class = util.dynamic_import_class(mw)
                app = app_class(self, self.application, config)
            elif type(mw) is dict:
                # If a dict with one entry is passed, expect {class: ..., kwargs: ...}
                expand = {"${application}": self.application}
                app = util.dynamic_instantiate_class_from_opts(mw, expand=expand)
            elif inspect.isclass(mw):
                # If a class is passed, assume BaseMiddleware (or compatible)
                # TODO: remove this assert with 3.0
                assert issubclass(mw, BaseMiddleware)
                app = mw(self, self.application, config)
            else:
                # Otherwise assume an initialized middleware instance
                app = mw

            # Remember
            if isinstance(app, HTTPAuthenticator):
                self.http_authenticator = app
                domain_controller = app.get_domain_controller()

            # Add middleware to the stack
            if app:
                if callable(getattr(app, "is_disabled", None)) and app.is_disabled():
                    _logger.warning(f"App {app}.is_disabled() returned True: skipping.")
                else:
                    mw_list.append(app)
                    self.application = app
            else:
                _logger.error(f"Could not add middleware {mw}.")

        _logger.info(
            f"WsgiDAV/{__version__} Python/{util.PYTHON_VERSION} {platform.platform(aliased=True)}"
        )

        if self.verbose >= 4:
            _logger.info(
                f"Default encoding: {sys.getdefaultencoding()!r} (file system: {sys.getfilesystemencoding()!r})"
            )

        if self.verbose >= 3:
            _logger.info(f"Lock manager:      {self.lock_manager}")
            _logger.info(f"Property manager:  {self.prop_manager}")
            _logger.info(f"Domain controller: {domain_controller}")

        if self.verbose >= 4:
            # We traversed the stack in reverse order. Now revert again, so
            # we see the order that was configured:
            _logger.info("Middleware stack:")
            for mw in reversed(mw_list):
                _logger.info(f"  - {mw}")

        if auth_conf.get("accept_basic") and not config.get("ssl_certificate"):
            _logger.warning(
                "Basic authentication is enabled: It is highly recommended to enable SSL."
            )

        if domain_controller:
            for share, provider in self.provider_map.items():
                if domain_controller.is_share_anonymous(share):
                    _logger.warning(
                        "Share {!r} will allow anonymous {} access.".format(
                            share, "read" if provider.is_readonly() else "write"
                        )
                    )

        if self.mount_path:
            _logger.info(f"Configured mount path: {self.mount_path!r}.")

        return

    def add_provider(self, share, provider, *, readonly=False):
        """Add a provider to the provider_map routing table."""
        # Make sure share starts with, or is '/'
        share = "/" + share.strip("/")
        assert share not in self.provider_map

        fs_opts = self.config.get("fs_dav_provider") or {}

        if type(provider) is str:
            # Syntax:
            #   <share_path>: <folder_path>
            # We allow a simple string as 'provider'. In this case we interpret
            # it as a file system root folder that is published.
            provider = util.fix_path(provider, self.config)
            provider = FilesystemProvider(provider, readonly=readonly, fs_opts=fs_opts)

        elif type(provider) is dict:
            if "class" in provider:
                # Syntax:
                #   <share_path>: {"class": <class_path>, "args": <pos_args>, "kwargs": <named_args>}
                expand = {"${application}": self}
                provider = util.dynamic_instantiate_class_from_opts(
                    provider, expand=expand
                )
            elif "root" in provider:
                # Syntax:
                #   <share_path>: {"root": <path>, "redaonly": <bool>}
                provider = FilesystemProvider(
                    util.fix_path(provider["root"], self.config),
                    readonly=bool(provider.get("readonly", False)),
                    fs_opts=fs_opts,
                )
            else:
                raise ValueError(
                    f"Provider expected {{'class': ...}}` or {{'root': ...}}: {provider}"
                )

        elif type(provider) in (list, tuple):
            raise ValueError(
                f"Provider {provider}: tuple/list syntax is no longer supported"
            )

        if not isinstance(provider, DAVProvider):
            raise ValueError(
                f"Invalid provider {provider} (not instance of DAVProvider)"
            )

        provider.set_share_path(share)
        if self.mount_path:
            provider.set_mount_path(self.mount_path)

        # TODO: someday we may want to configure different lock/prop
        # managers per provider
        provider.set_lock_manager(self.lock_manager)
        provider.set_prop_manager(self.prop_manager)

        self.provider_map[share] = provider
        # self.provider_map[share] = {"provider": provider, "allow_anonymous": False}

        # Store the list of share paths, ordered by length, so route lookups
        # will return the most specific match
        self.sorted_share_list = [s.lower() for s in self.provider_map.keys()]
        self.sorted_share_list = sorted(self.sorted_share_list, key=len, reverse=True)

        return provider

    def resolve_provider(self, path):
        """Get the registered DAVProvider for a given path.

        Returns:
            tuple: (share, provider)
        """
        # Find DAV provider that matches the share
        share = None
        lower_path = path.lower()
        for r in self.sorted_share_list:
            # @@: Case sensitivity should be an option of some sort here;
            # os.path.normpath might give the preferred case for a filename.
            if r == "/":
                share = r
                break
            elif lower_path == r or lower_path.startswith(r + "/"):
                share = r
                break

        if share is None:
            return None, None

        return share, self.provider_map.get(share)

    async def __call__(self, scope, receive, send):
        scope = HTTPScope(scope)

        path: str = scope.path

        # We optionally unquote PATH_INFO here, although this should already be
        # done by the server (#8, #228).
        if self.unquote_path_info:
            path = unquote(scope.path)

        # GC issue 22: Pylons sends root as u'/'
        if not util.is_str(path):
            _logger.warning(f"Got non-native path: {path!r}")
            # path = path.encode("utf8")
            path = util.to_str(path)

        # Always adding these values to scope:
        scope.asgidav.config = self.config
        scope.asgidav.provider = None
        scope.asgidav.verbose = self.verbose

        # Find DAV provider that matches the share
        share, provider = self.resolve_provider(path)

        # Note: we call the next app, even if provider is None, because OPTIONS
        #       must still be handled.
        #       All other requests will result in '404 Not Found'
        scope.asgidav.provider = provider

        # TODO: test with multi-level realms: 'aa/bb'
        # TODO: test security: url contains '..'

        # Transform SCRIPT_NAME and PATH_INFO
        # (Since path and share are unquoted, this also fixes quoted values.)
        if share == "/" or not share:
            scope.path = path
        else:
            scope.root_path += share
            scope.path = path[len(share) :]

        assert util.is_str(path)
        # See http://mail.python.org/pipermail/web-sig/2007-January/002475.html
        # for some clarification about SCRIPT_NAME/PATH_INFO format
        # SCRIPT_NAME starts with '/' or is empty
        assert scope.root_path == "" or scope.root_path.startswith("/")
        # SCRIPT_NAME must not have a trailing '/'
        assert scope.root_path in ("", "/") or not scope.root_path.endswith("/")
        # PATH_INFO starts with '/'
        assert path == "" or path.startswith("/")

        server = RequestServer(provider)

        await server(scope, receive, send)
