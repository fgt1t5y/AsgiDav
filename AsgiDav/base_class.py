from abc import ABC, abstractmethod
from typing import (
    Any,
    Awaitable,
    Callable,
    Iterable,
    Literal,
    TypedDict,
    Union,
)
from urllib.parse import unquote

from AsgiDav import util
from AsgiDav.lock_man.lock_manager import LockManager
from AsgiDav.prop_man.property_manager import PropertyManager


class DAVProvider(ABC):
    """Abstract base class for DAV resource providers.

    There will be only one DAVProvider instance per share (not per request).
    """

    def __init__(self):
        self.mount_path = ""
        self.share_path: str | None = None
        self.lock_manager: LockManager | None = None
        self.prop_manager: PropertyManager | None = None
        self.verbose: int = 3

        self._count_get_resource_inst = 0
        self._count_get_resource_inst_init = 0

        # self.caseSensitiveUrls = True

    def __repr__(self):
        return self.__class__.__name__

    def is_readonly(self):
        return False

    def set_mount_path(self, mount_path):
        """Set application root for this resource provider.

        This is the value of SCRIPT_NAME, when AsgiDavApp is called.
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
        return "/" + unquote(util.removeprefix(ref_url, self.share_path)).lstrip("/")  # type: ignore

    @abstractmethod
    def get_resource_inst(self, path: str, scope: "HTTPScope"):
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

    def exists(self, path: str, scope: "HTTPScope"):
        """Return True, if path maps to an existing resource.

        This method should only be used, if no other information is queried
        for <path>. Otherwise a _DAVResource should be created first.

        This method SHOULD be overridden by a more efficient implementation.
        """
        return self.get_resource_inst(path, scope) is not None

    def is_collection(self, path: str, scope: "HTTPScope"):
        """Return True, if path maps to an existing collection resource.

        This method should only be used, if no other information is queried
        for <path>. Otherwise a _DAVResource should be created first.
        """
        res = self.get_resource_inst(path, scope)

        return res and res.is_collection

    def custom_request_handler(self, scope, receive, send, default_handler):
        """Optionally implement custom request handling.

        requestmethod = environ["REQUEST_METHOD"]
        Either

        - handle the request completely
        - do additional processing and call default_handler(environ, start_response)
        """
        return default_handler(scope, receive, send)


class ASGIVersions(TypedDict):
    spec_version: str
    version: Literal["2.0"] | Literal["3.0"]


class AsgiDavAuth:
    realm: str
    user_name: str | None
    roles: list[str] | None
    permissions: list[str] | None


class AsgiDavConditions:
    _if: dict[str, Any] | None

    def __init__(self) -> None:
        self._if = None


class AsgiDavContext:
    config: dict[str, Any]
    provider: DAVProvider | None
    verbose: int
    auth: AsgiDavAuth
    user_name: str
    conditions: AsgiDavConditions
    ifLockTokenList: list[Any]
    debug_break: bool | None
    dump_request_body: str | bool | None
    dump_response_body: str | bool | None
    all_input_read: int | None

    def __init__(self) -> None:
        self.debug_break = False
        self.auth = AsgiDavAuth()
        self.conditions = AsgiDavConditions()

        self.auth.user_name = None
        self.auth.roles = []


# HTTPScope with context
class HTTPScope:
    type: Literal["http"]
    asgi: ASGIVersions
    http_version: str
    method: str
    scheme: str
    path: str
    raw_path: bytes
    query_string: bytes
    root_path: str
    headers: dict[str, Any]
    client: tuple[str, int] | None
    server: tuple[str, int | None] | None
    url_scheme: str

    HTTP_DEPTH: str | None
    HTTP_OVERWRITE: str | None
    HTTP_EXPECT: str | None
    HTTP_IF: str | None
    HTTP_IF_MODIFIED_SINCE: str | None
    HTTP_IF_UNMODIFIED_SINCE: str | None
    HTTP_IF_MATCH: str | None
    HTTP_CONTENT_ENCODING: str | None
    HTTP_CONTENT_RANGE: str | None
    CONTENT_TYPE: str | None
    CONTENT_LENGTH: str
    HTTP_DESTINATION: str | None
    HTTP_X_FORWARDED_PROTO: str | None
    HTTP_HOST: str
    HTTP_TIMEOUT: str | None
    HTTP_LOCK_TOKEN: str | None
    HTTP_RANGE: str | None
    HTTP_IF_RANGE: str | None
    HTTP_USER_AGENT: str | None
    HTTP_ORIGIN: str | None
    HTTP_ACCESS_CONTROL_REQUEST_METHOD: str | None
    HTTP_ACCESS_CONTROL_REQUEST_HEADERS: tuple[str, int] | None
    HTTP_CONNECTION: str | None
    HTTP_TRANSFER_ENCODING: str | None
    HTTP_AUTHORIZATION: str | None
    SERVER_NAME: str
    SERVER_PORT: str
    REQUEST_URI: str | None

    asgidav: AsgiDavContext

    def __init__(self, scope) -> None:
        self.type = "http"
        self.asgi = scope["asgi"]
        self.http_version = scope["http_version"]
        self.method = scope["method"]
        self.path = scope["path"]
        self.raw_path = scope["raw_path"]
        self.query_string = scope["query_string"]
        self.root_path = scope["root_path"]
        self.headers = self.headers_to_dict(scope["headers"])
        self.client = scope["client"]
        self.server = scope["server"]
        self.url_scheme = scope["scheme"] or "http"

        self.HTTP_DEPTH = self.headers.get("depth")
        self.HTTP_OVERWRITE = self.headers.get("overwrite")
        self.HTTP_EXPECT = self.headers.get("expect")
        self.HTTP_IF = self.headers.get("if")
        self.HTTP_IF_MODIFIED_SINCE = self.headers.get("if-modified-since")
        self.HTTP_IF_UNMODIFIED_SINCE = self.headers.get("if-unmodified-since")
        self.HTTP_IF_MATCH = self.headers.get("if-match")
        self.HTTP_IF_NONE_MATCH = self.headers.get("if-none-match")
        self.HTTP_CONTENT_ENCODING = self.headers.get("content-encoding")
        self.HTTP_CONTENT_RANGE = self.headers.get("content-range")
        self.CONTENT_TYPE = self.headers.get("content-type", "")
        self.CONTENT_LENGTH = self.headers.get("content-length", "")
        self.HTTP_DESTINATION = self.headers.get("destination")
        self.HTTP_X_FORWARDED_PROTO = self.headers.get("x-forwarded-proto", "")
        self.HTTP_HOST = self.headers["host"]
        self.HTTP_TIMEOUT = self.headers.get("timeout")
        self.HTTP_LOCK_TOKEN = self.headers.get("lock-token")
        self.HTTP_RANGE = self.headers.get("range")
        self.SERVER_NAME = self.server[0]  # type: ignore
        self.SERVER_PORT = self.server[1]  # type: ignore
        self.REQUEST_URI = self.headers.get("request-uri")
        self.HTTP_IF_RANGE = self.headers.get("if-range")
        self.HTTP_USER_AGENT = self.headers.get("user-agent")
        self.HTTP_ORIGIN = self.headers.get("origin")
        self.HTTP_ACCESS_CONTROL_REQUEST_METHOD = self.headers.get(
            "access-control-request-method"
        )
        self.HTTP_ACCESS_CONTROL_REQUEST_HEADERS = self.headers.get(
            "access-control-request-headers"
        )
        self.HTTP_CONNECTION = self.headers.get("connection")
        self.HTTP_TRANSFER_ENCODING = self.headers.get("transfer-encoding")
        self.HTTP_AUTHORIZATION = self.headers.get("authorization")

        self.asgidav = AsgiDavContext()

    def headers_to_dict(self, headers: Iterable[tuple[bytes, bytes]]):
        result: dict[str, str] = {}

        for key, value in headers:
            result[f"{key.decode()}"] = value.decode()

        return result


class HTTPRequestEvent(TypedDict):
    type: Literal["http.request"]
    body: bytes
    more_body: bool


class HTTPDisconnectEvent(TypedDict):
    type: Literal["http.disconnect"]


ASGIReceiveEvent = Union[
    HTTPRequestEvent,
    HTTPDisconnectEvent,
    # WebSocketConnectEvent,
    # WebSocketReceiveEvent,
    # WebSocketDisconnectEvent,
    # LifespanStartupEvent,
    # LifespanShutdownEvent,
]


class HTTPResponseStartEvent(TypedDict):
    type: Literal["http.response.start"]
    status: int
    headers: Iterable[tuple[bytes, bytes]]
    trailers: bool


class HTTPResponseBodyEvent(TypedDict):
    type: Literal["http.response.body"]
    body: bytes
    more_body: bool


ASGISendEvent = Union[
    HTTPResponseStartEvent,
    HTTPResponseBodyEvent,
    # HTTPResponseTrailersEvent,
    # HTTPServerPushEvent,
    # HTTPDisconnectEvent,
    # WebSocketAcceptEvent,
    # WebSocketSendEvent,
    # WebSocketResponseStartEvent,
    # WebSocketResponseBodyEvent,
    # WebSocketCloseEvent,
    # LifespanStartupCompleteEvent,
    # LifespanStartupFailedEvent,
    # LifespanShutdownCompleteEvent,
    # LifespanShutdownFailedEvent,
]


ASGIReceiveCallable = Callable[[], Awaitable[ASGIReceiveEvent]]
ASGISendCallable = Callable[[ASGISendEvent], Awaitable[None]]
