# (c) 2009-2024 Martin Wendt and contributors; see WsgiDAV https://github.com/mar10/wsgidav
# Licensed under the MIT license:
# http://www.opensource.org/licenses/mit-license.php
"""
    Test helpers.

Example:
    with AsgiDavTestServer(opts):
        ... test methods
"""

import multiprocessing
import os
import shutil
import sys
import time
from tempfile import gettempdir

import uvicorn

from AsgiDav import util
from AsgiDav.app import AsgiDavApp
from AsgiDav.fs_dav_provider import FilesystemProvider

FIXTURE_PATH = os.path.join(os.path.dirname(__file__), "fixtures")

# ========================================================================
# Timing
# ========================================================================


class Timing:
    """Print timing"""

    def __init__(self, name, count=None, fmt=None, count2=None, fmt2=None, stream=None):
        self.name = name
        self.count = count
        self.fmt = fmt
        self.count2 = count2
        self.fmt2 = fmt2
        self.stream = stream or sys.stdout

    def __enter__(self):
        self.start = time.time()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        elap = time.time() - self.start
        msg = [f"Timing {repr(self.name):<20} took {elap:>6.3f} sec"]
        if self.count:
            fmt = self.fmt or "{:0,.1f} bytes/sec"
            msg.append(fmt.format(float(self.count) / elap))
        if self.count2:
            fmt = self.fmt2 or "{:0,.1f} bytes/sec"
            msg.append(fmt.format(float(self.count2) / elap))
        print(", ".join(msg))


# ==============================================================================
# write_test_file
# ==============================================================================


def write_test_file(name, size):
    path = os.path.join(gettempdir(), name)
    with open(path, "wb") as f:
        f.write(b"*" * size)
    return path


def create_test_folder(name):
    path = os.path.join(gettempdir(), name)
    # copytree fails if dir exists. Since Py3.8 we could add `dirs_exist_ok=True`
    # but this would break tests on 3.6/3.7.
    shutil.rmtree(util.to_str(path), ignore_errors=True)
    shutil.copytree(os.path.join(FIXTURE_PATH, "share"), path)
    return path


# ==============================================================================
# make_asgidav_app
# ==============================================================================


def make_asgidav_app(with_auth, with_ssl, provider=None):
    """Start blocking WsgiDAV server (called as a separate process)."""

    package_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    share_path = os.path.join(gettempdir(), "wsgidav-test")

    if not os.path.exists(share_path):
        os.mkdir(share_path)

    if provider is None:
        provider = FilesystemProvider(share_path, readonly=False, fs_opts={})

    config = {
        "host": "127.0.0.1",
        "port": 8080,
        "provider_mapping": {"/": provider},
        # None: dc.simple_dc.SimpleDomainController(user_mapping)
        "http_authenticator": {"domain_controller": None},
        "simple_dc": {"user_mapping": {"*": True}},  # anonymous access
        "verbose": 1,
        "logging": {
            "enable_loggers": [],
            # "debug_methods": [],
        },
        "property_manager": True,  # True: use property_manager.PropertyManager
        "lock_storage": True,  # True: use LockManager(lock_storage.LockStorageDict)
    }

    if with_auth:
        config["http_authenticator"].update(
            {"accept_basic": True, "accept_digest": False, "default_to_digest": False}
        )
        config["simple_dc"].update(
            {
                "user_mapping": {
                    "*": {
                        "tester": {
                            "password": "secret",
                            "description": "",
                            "roles": [],
                        },
                        "tester2": {
                            "password": "secret2",
                            "description": "",
                            "roles": [],
                        },
                    }
                }
            }
        )

    if with_ssl:
        config.update(
            {
                "ssl_certificate": os.path.join(
                    package_path, "AsgiDav/server/sample_bogo_server.crt"
                ),
                "ssl_private_key": os.path.join(
                    package_path, "AsgiDav/server/sample_bogo_server.key"
                ),
                "ssl_certificate_chain": None,
                # "accept_digest": True,
                # "default_to_digest": True,
            }
        )

    # We want output captured for tests
    util.init_logging(config)

    return AsgiDavApp(config)


# ========================================================================
# AsgiDavTestServer
# ========================================================================


class AsgiDavTestServer:
    """Run AsgiDav in a separate process."""

    def __init__(
        self,
        config=None,
        with_auth=False,
        with_ssl=False,
        provider=None,
        profile=False,
        app=None,
    ):
        self.app = app
        self.config = config
        self.with_auth = with_auth
        self.with_ssl = with_ssl
        self.provider = provider
        self.startup_event = multiprocessing.Event()
        self.startup_timeout = 5
        self.proc = None

        assert not profile, "Not yet implemented"

    def __enter__(self):
        self.start()

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()

    def __del__(self):
        try:
            self.stop()
        except Exception:
            pass

    def serve(self):
        uvicorn.run(
            self.app
            if self.app
            else make_asgidav_app(self.with_auth, self.with_ssl, self.provider),
            host="127.0.0.1",
            port=8080,
        )

    def start(self):
        print("Starting AsgiDavTestServer...")

        self.proc = multiprocessing.Process(target=self.serve)
        self.proc.start()

        print("Starting AsgiDavTestServer... waiting for request loop...")
        print("Starting AsgiDavTestServer... running.")

        time.sleep(1)

    def stop(self):
        if self.proc and self.proc.is_alive():
            print("Stopping AsgiDavTestServer...")

            self.proc.terminate()
            self.proc.join()
            self.proc = None

        print("Stopping AsgiDavTestServer... done.")
