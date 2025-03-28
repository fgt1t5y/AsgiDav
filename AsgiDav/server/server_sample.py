# (c) 2009-2024 Martin Wendt and contributors; see WsgiDAV https://github.com/mar10/wsgidav
# Original PyFileServer (c) 2005 Ho Chun Wei.
# Licensed under the MIT license: http://www.opensource.org/licenses/mit-license.php
"""
Simple example how to a run AsgiDav in a 3rd-party ASGI server.
"""

import uvicorn

from AsgiDav.app import AsgiDavApp
from AsgiDav.fs_dav_provider import FilesystemProvider
from AsgiDav.mw.error_printer import ErrorPrinter
from AsgiDav.mw.request_resolver import RequestResolver

if __name__ == "__main__":
    root_path = "."
    provider = FilesystemProvider(root_path, readonly=False, fs_opts={})

    config = {
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
        "middleware_stack": [ErrorPrinter, RequestResolver],
        "cors": {"allow_origin": "*"},
    }

    app = AsgiDavApp(config)
    config = uvicorn.Config(app=app, host="127.0.0.1", port=8080)
    server = uvicorn.Server(config=config)
    server.run()
