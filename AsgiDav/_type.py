from typing import (
    Any,
    Awaitable,
    Callable,
    Iterable,
    Literal,
    NotRequired,
    TypedDict,
    Union,
)

from AsgiDav.fs_dav_provider import DAVProvider


class ASGIVersions(TypedDict):
    spec_version: str
    version: Literal["2.0"] | Literal["3.0"]


class AsgiDavAuth:
    user_name: str | None


class AsgiConditionsContext:
    _if: dict[str, Any] | None


class AsgiDavContext:
    config: dict[str, Any]
    provider: DAVProvider | None
    verbose: int
    auth: AsgiDavAuth
    user_name: str
    conditions: AsgiConditionsContext
    ifLockTokenList: list[Any]
    debug_break: bool | None
    dump_response_body: str | None
    all_input_read: int | None

    def __init__(self) -> None:
        pass


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
    headers: dict[str, str]
    client: tuple[str, int] | None
    server: tuple[str, int | None] | None
    url_scheme: str
    # state: NotRequired[dict[str, Any]]
    # extensions: NotRequired[dict[str, dict[object, object]]]

    HTTP_DEPTH: str | None
    HTTP_OVERWRITE: Literal["T"] | Literal["F"] | None
    HTTP_EXPECT: str | None
    HTTP_IF: str | None
    HTTP_IF_MODIFIED_SINCE: str | None
    HTTP_IF_UNMODIFIED_SINCE: str | None
    HTTP_IF_MATCH: str | None
    HTTP_CONTENT_ENCODING: str | None
    HTTP_CONTENT_RANGE: str | None
    CONTENT_TYPE: str | None
    CONTENT_LENGTH: str | None
    HTTP_DESTINATION: str | None
    HTTP_X_FORWARDED_PROTO: str
    HTTP_HOST: str
    HTTP_TIMEOUT: str | None
    HTTP_LOCK_TOKEN: str | None
    HTTP_RANGE: str | None
    HTTP_IF_RANGE: str | None
    SERVER_NAME: str
    SERVER_PORT: str

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
        self.headers = self.headers_to_dict(scope["header"])
        self.client = scope["client"]
        self.server = scope["server"]
        self.url_scheme = scope["scheme"] or "http"

        self.HTTP_DEPTH = self.headers["depth"]
        self.HTTP_OVERWRITE = self.headers["overwrite"]  # type: ignore
        self.HTTP_EXPECT = self.headers["expect"]
        self.HTTP_IF = self.headers["if"]
        self.HTTP_IF_MODIFIED_SINCE = self.headers["if-modified-since"]
        self.HTTP_IF_UNMODIFIED_SINCE = self.headers["if-unmodified-since"]
        self.HTTP_IF_MATCH = self.headers["if-match"]
        self.HTTP_IF_NONE_MATCH = self.headers["if-none-match"]
        self.HTTP_CONTENT_ENCODING = self.headers["content-encoding"]
        self.HTTP_CONTENT_RANGE = self.headers["content-range"]
        self.CONTENT_TYPE = self.headers["content-type"]
        self.CONTENT_LENGTH = self.headers["content-length"]
        self.HTTP_DESTINATION = self.headers["destination"]
        self.HTTP_X_FORWARDED_PROTO = self.headers["x-forwarded-proto"]
        self.HTTP_HOST = self.headers["host"]
        self.HTTP_TIMEOUT = self.headers["timeout"]
        self.HTTP_LOCK_TOKEN = self.headers["lock-token"]
        self.HTTP_RANGE = self.headers["range"]
        self.SERVER_NAME = self.server[0]  # type: ignore
        self.SERVER_PORT = self.server[1]  # type: ignore
        self.HTTP_IF_RANGE = self.headers["if-range"]

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
    headers: NotRequired[Iterable[tuple[bytes, bytes]]]
    trailers: NotRequired[bool]


class HTTPResponseBodyEvent(TypedDict):
    type: Literal["http.response.body"]
    body: bytes
    more_body: NotRequired[bool]


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
