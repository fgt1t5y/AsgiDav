from abc import ABC, abstractmethod
from urllib.parse import unquote

from AsgiDav import util


class DAVProvider(ABC):
    """Abstract base class for DAV resource providers.

    There will be only one DAVProvider instance per share (not per request).
    """

    def __init__(self):
        self.mount_path = ""
        self.share_path = None
        self.lock_manager = None
        self.prop_manager = None
        self.verbose = 3

        self._count_get_resource_inst = 0
        self._count_get_resource_inst_init = 0

        # self.caseSensitiveUrls = True

    def __repr__(self):
        return self.__class__.__name__

    def is_readonly(self):
        return False

    def set_mount_path(self, mount_path):
        """Set application root for this resource provider.

        This is the value of SCRIPT_NAME, when WsgiDAVApp is called.
        """
        assert mount_path in ("", "/") or (
            mount_path.startswith("/") and not mount_path.endswith("/")
        )
        self.mount_path = mount_path

    def set_share_path(self, share_path):
        """Set application location for this resource provider.

        @param share_path: a UTF-8 encoded, unquoted byte string.
        """
        # if isinstance(share_path, unicode):
        #     share_path = share_path.encode("utf8")
        assert share_path == "" or share_path.startswith("/")
        if share_path == "/":
            share_path = ""  # This allows to code 'absPath = share_path + path'
        assert share_path in ("", "/") or not share_path.endswith("/")
        self.share_path = share_path

    def set_lock_manager(self, lock_manager):
        if lock_manager and not hasattr(lock_manager, "check_write_permission"):
            raise ValueError(
                "Must be compatible with wsgidav.lock_man.lock_manager.LockManager"
            )
        self.lock_manager = lock_manager

    def set_prop_manager(self, prop_manager):
        if prop_manager and not hasattr(prop_manager, "copy_properties"):
            raise ValueError(
                "Must be compatible with wsgidav.prop_man.property_manager.PropertyManager"
            )
        self.prop_manager = prop_manager

    def ref_url_to_path(self, ref_url):
        """Convert a refUrl to a path, by stripping the share prefix.

        Used to calculate the <path> from a storage key by inverting get_ref_url().
        """
        return "/" + unquote(util.removeprefix(ref_url, self.share_path)).lstrip("/")

    @abstractmethod
    def get_resource_inst(self, path: str, environ: dict):
        """Return a _DAVResource object for path.

        Should be called only once per request and resource::

            res = provider.get_resource_inst(path, environ)
            if res and not res.is_collection:
                print(res.get_content_type())

        If <path> does not exist, None is returned.
        <environ> may be used by the provider to implement per-request caching.

        See _DAVResource for details.

        This method MUST be implemented.
        """
        raise NotImplementedError

    def exists(self, path: str, environ: dict):
        """Return True, if path maps to an existing resource.

        This method should only be used, if no other information is queried
        for <path>. Otherwise a _DAVResource should be created first.

        This method SHOULD be overridden by a more efficient implementation.
        """
        return self.get_resource_inst(path, environ) is not None

    def is_collection(self, path: str, environ: dict):
        """Return True, if path maps to an existing collection resource.

        This method should only be used, if no other information is queried
        for <path>. Otherwise a _DAVResource should be created first.
        """
        res = self.get_resource_inst(path, environ)
        return res and res.is_collection

    def custom_request_handler(self, environ, start_response, default_handler):
        """Optionally implement custom request handling.

        requestmethod = environ["REQUEST_METHOD"]
        Either

        - handle the request completely
        - do additional processing and call default_handler(environ, start_response)
        """
        return default_handler(environ, start_response)
