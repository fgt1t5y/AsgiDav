from AsgiDav.app import AsgiDavApp
from AsgiDav.fs_dav_provider import FilesystemProvider
from AsgiDav.mw.request_resolver import RequestResolver

root_path = "D:/data"
provider = FilesystemProvider(root_path, readonly=False, fs_opts={})

config = {
    "host": "127.0.0.1",
    "port": 8080,
    "provider_mapping": {"/": provider},
    "http_authenticator": {
        "domain_controller": None  # None: dc.simple_dc.SimpleDomainController(user_mapping)
    },
    "simple_dc": {"user_mapping": {"*": True}},  # anonymous access
    "verbose": 3,
    "logging": {
        "enable": True,
        "enable_loggers": [],
    },
    "property_manager": True,  # True: use property_manager.PropertyManager
    "lock_storage": True,  # True: use LockManager(lock_storage.LockStorageDict)
    "middleware_stack": [RequestResolver],
    "cors": {"allow_origin": "*"},
}

app = AsgiDavApp(config)
