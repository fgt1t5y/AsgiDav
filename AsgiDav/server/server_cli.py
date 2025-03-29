"""
server_cli
==========

:Author: Martin Wendt
:Copyright: Licensed under the MIT license, see LICENSE file in this package.

Standalone server that runs WsgiDAV.

These tasks are performed:

    - Set up the configuration from defaults, configuration file, and command line
      options.
    - Instantiate the AsgiDavApp object (which is a WSGI application)
    - Start a WSGI server for this AsgiDavApp object

Configuration is defined like this:

    1. Get the name of a configuration file from command line option
       ``--config-file=FILENAME`` (or short ``-cFILENAME``).
       If this option is omitted, we use ``wsgidav.yaml`` in the current
       directory.
    2. Set reasonable default settings.
    3. If configuration file exists: read and use it to overwrite defaults.
    4. If command line options are passed, use them to override settings:

       ``--host`` option overrides ``hostname`` setting.

       ``--port`` option overrides ``port`` setting.

       ``--root=FOLDER`` option creates a FilesystemProvider that publishes
       FOLDER on the '/' share.
"""

import argparse
import copy
import logging
import os
import platform
import sys
import webbrowser
from pprint import pformat
from threading import Timer

import yaml

from AsgiDav import __version__, util
from AsgiDav.app import AsgiDavApp
from AsgiDav.default_conf import DEFAULT_CONFIG, DEFAULT_VERBOSE
from AsgiDav.fs_dav_provider import FilesystemProvider
from AsgiDav.xml_tools import use_lxml

try:
    # Try pyjson5 first because it's faster than json5
    from pyjson5 import load as json_load
except ImportError:
    from json5 import load as json_load


__docformat__ = "reStructuredText"

#: Try this config files if no --config=... option is specified
DEFAULT_CONFIG_FILES = ("wsgidav.yaml", "wsgidav.json")

_logger = logging.getLogger("wsgidav")


def _get_common_info(config):
    """Calculate some common info."""
    # Support SSL
    ssl_certificate = util.fix_path(config.get("ssl_certificate"), config)
    ssl_private_key = util.fix_path(config.get("ssl_private_key"), config)
    ssl_certificate_chain = util.fix_path(config.get("ssl_certificate_chain"), config)
    ssl_adapter = config.get("ssl_adapter", "builtin")
    use_ssl = False
    if ssl_certificate and ssl_private_key:
        use_ssl = True
        # _logger.info("SSL / HTTPS enabled. Adapter: {}".format(ssl_adapter))
    elif ssl_certificate or ssl_private_key:
        raise RuntimeError(
            "Option 'ssl_certificate' and 'ssl_private_key' must be used together."
        )

    protocol = "https" if use_ssl else "http"
    url = f"{protocol}://{config['host']}:{config['port']}"
    info = {
        "use_ssl": use_ssl,
        "ssl_cert": ssl_certificate,
        "ssl_pk": ssl_private_key,
        "ssl_adapter": ssl_adapter,
        "ssl_chain": ssl_certificate_chain,
        "protocol": protocol,
        "url": url,
    }
    return info


class FullExpandedPath(argparse.Action):
    """Expand user- and relative-paths"""

    def __call__(self, parser, namespace, values, option_string=None):
        new_val = os.path.abspath(os.path.expanduser(values))
        setattr(namespace, self.dest, new_val)


def _init_command_line_options():
    """Parse command line options into a dictionary."""
    description = """\

Run a WEBDAV server to share file system folders.

Examples:

  Share filesystem folder '/temp' for anonymous access (no config file used):
    wsgidav --port=80 --host=0.0.0.0 --root=/temp --auth=anonymous

  Run using a specific configuration file:
    wsgidav --port=80 --host=0.0.0.0 --config=~/my_wsgidav.yaml

  If no config file is specified, the application will look for a file named
  'wsgidav.yaml' in the current directory.
  See
    http://wsgidav.readthedocs.io/en/latest/run-configure.html
  for some explanation of the configuration file format.
  """

    epilog = """\
Licensed under the MIT license.
See https://github.com/mar10/wsgidav for additional information.

"""

    parser = argparse.ArgumentParser(
        prog="asgidav",
        description=description,
        epilog=epilog,
        allow_abbrev=False,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        # default=8080,
        help="port to serve on (default: 8080)",
    )
    parser.add_argument(
        "-H",  # '-h' conflicts with --help
        "--host",
        help=(
            "host to serve from (default: localhost). 'localhost' is only "
            "accessible from the local computer. Use 0.0.0.0 to make your "
            "application public"
        ),
    )
    parser.add_argument(
        "-r",
        "--root",
        dest="root_path",
        action=FullExpandedPath,
        help="path to a file system folder to publish for RW as share '/'.",
    )
    parser.add_argument(
        "--auth",
        choices=("anonymous", "nt", "pam-login"),
        help="quick configuration of a domain controller when no config file is used",
    )
    # parser.add_argument(
    #     "--server",
    #     choices=SUPPORTED_SERVERS.keys(),
    #     # default="cheroot",
    #     help="type of pre-installed WSGI server to use (default: cheroot).",
    # )
    parser.add_argument(
        "--ssl-adapter",
        choices=("builtin", "pyopenssl"),
        # default="builtin",
        help="used by 'cheroot' server if SSL certificates are configured "
        "(default: builtin).",
    )

    qv_group = parser.add_mutually_exclusive_group()
    qv_group.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=3,
        help="increment verbosity by one (default: %(default)s, range: 0..5)",
    )
    qv_group.add_argument(
        "-q", "--quiet", default=0, action="count", help="decrement verbosity by one"
    )

    qv_group = parser.add_mutually_exclusive_group()
    qv_group.add_argument(
        "-c",
        "--config",
        dest="config_file",
        action=FullExpandedPath,
        help=(
            f"configuration file (default: {DEFAULT_CONFIG_FILES} in current directory)"
        ),
    )

    qv_group.add_argument(
        "--no-config",
        action="store_true",
        help=f"do not try to load default {DEFAULT_CONFIG_FILES}",
    )

    parser.add_argument(
        "--browse",
        action="store_true",
        help="open browser on start",
    )

    parser.add_argument(
        "-V",
        "--version",
        action="store_true",
        help="print version info and exit (may be combined with --verbose)",
    )

    args = parser.parse_args()

    args.verbose -= args.quiet
    del args.quiet

    if args.root_path and not os.path.isdir(args.root_path):
        msg = f"{args.root_path} is not a directory"
        parser.error(msg)

    if args.version:
        if args.verbose >= 4:
            version_info = "AsgiDav/{} {}/{}({} bit) {}".format(
                __version__,
                platform.python_implementation(),
                util.PYTHON_VERSION,
                "64" if sys.maxsize > 2**32 else "32",
                platform.platform(aliased=True),
            )
            version_info += f"\nPython from: {sys.executable}"
        else:
            version_info = f"{__version__}"
        print(version_info)
        sys.exit()

    if args.no_config:
        pass
        # ... else ignore default config files
    elif args.config_file is None:
        # If --config was omitted, use default (if it exists)
        for filename in DEFAULT_CONFIG_FILES:
            defPath = os.path.abspath(filename)
            if os.path.exists(defPath):
                if args.verbose >= 3:
                    print(f"Using default configuration file: {defPath}")
                args.config_file = defPath
                break
    else:
        # If --config was specified convert to absolute path and assert it exists
        args.config_file = os.path.abspath(args.config_file)
        if not os.path.isfile(args.config_file):
            parser.error(
                f"Could not find specified configuration file: {args.config_file}"
            )

    # Convert args object to dictionary
    cmdLineOpts = args.__dict__.copy()
    if args.verbose >= 5:
        print("Command line args:")
        for k, v in cmdLineOpts.items():
            print(f"    {k:>12}: {v}")

    return cmdLineOpts, parser


def _read_config_file(config_file, _verbose):
    """Read configuration file options into a dictionary."""

    config_file = os.path.abspath(config_file)

    if not os.path.exists(config_file):
        raise RuntimeError(f"Couldn't open configuration file {config_file!r}.")

    if config_file.endswith(".json"):
        with open(config_file, encoding="utf-8-sig") as fp:
            conf = json_load(fp)

    elif config_file.endswith(".yaml"):
        with open(config_file, encoding="utf-8-sig") as fp:
            conf = yaml.safe_load(fp)

    else:
        raise RuntimeError(
            f"Unsupported config file format (expected yaml or json): {config_file}"
        )

    conf["_config_file"] = config_file
    conf["_config_root"] = os.path.dirname(config_file)
    return conf


def _init_config():
    """Setup configuration dictionary from default, command line and configuration file."""
    cli_opts, parser = _init_command_line_options()
    cli_verbose = cli_opts["verbose"]

    # Set config defaults
    config = copy.deepcopy(DEFAULT_CONFIG)
    config["_config_file"] = None
    config["_config_root"] = os.getcwd()

    # Configuration file overrides defaults
    config_file = cli_opts.get("config_file")
    if config_file:
        file_opts = _read_config_file(config_file, cli_verbose)
        util.deep_update(config, file_opts)
        if cli_verbose != DEFAULT_VERBOSE and "verbose" in file_opts:
            if cli_verbose >= 2:
                print(
                    "Config file defines 'verbose: {}' but is overridden by command line: {}.".format(
                        file_opts["verbose"], cli_verbose
                    )
                )
            config["verbose"] = cli_verbose
    else:
        if cli_verbose >= 2:
            print("Running without configuration file.")

    # Command line overrides file
    if cli_opts.get("port"):
        config["port"] = cli_opts.get("port")
    if cli_opts.get("host"):
        config["host"] = cli_opts.get("host")
    if cli_opts.get("profile") is not None:
        config["profile"] = True
    if cli_opts.get("server") is not None:
        config["server"] = cli_opts.get("server")
    if cli_opts.get("ssl_adapter") is not None:
        config["ssl_adapter"] = cli_opts.get("ssl_adapter")

    # Command line overrides file only if -v or -q where passed:
    if cli_opts.get("verbose") != DEFAULT_VERBOSE:
        config["verbose"] = cli_opts.get("verbose")

    if cli_opts.get("root_path"):
        root_path = os.path.abspath(cli_opts.get("root_path"))
        config["provider_mapping"]["/"] = FilesystemProvider(
            root_path,
            fs_opts=config.get("fs_dav_provider"),
        )

    if config["verbose"] >= 5:
        # TODO: remove passwords from user_mapping
        config_cleaned = util.purge_passwords(config)
        print(
            "Configuration({}):\n{}".format(
                cli_opts["config_file"], pformat(config_cleaned)
            )
        )

    if not config["provider_mapping"]:
        parser.error("No DAV provider defined.")

    # Quick-configuration of DomainController
    auth = cli_opts.get("auth")
    auth_conf = util.get_dict_value(config, "http_authenticator", as_dict=True)
    if auth and auth_conf.get("domain_controller"):
        parser.error(
            "--auth option can only be used when no domain_controller is configured"
        )

    if auth == "anonymous":
        if config["simple_dc"]["user_mapping"]:
            parser.error(
                "--auth=anonymous can only be used when no user_mapping is configured"
            )
        auth_conf.update(
            {
                "domain_controller": "wsgidav.dc.simple_dc.SimpleDomainController",
                "accept_basic": True,
                "accept_digest": True,
                "default_to_digest": True,
            }
        )
        config["simple_dc"]["user_mapping"] = {"*": True}
    elif auth == "nt":
        if config.get("nt_dc"):
            parser.error(
                "--auth=nt can only be used when no nt_dc settings are configured"
            )
        auth_conf.update(
            {
                "domain_controller": "wsgidav.dc.nt_dc.NTDomainController",
                "accept_basic": True,
                "accept_digest": False,
                "default_to_digest": False,
            }
        )
        config["nt_dc"] = {}
    elif auth == "pam-login":
        if config.get("pam_dc"):
            parser.error(
                "--auth=pam-login can only be used when no pam_dc settings are configured"
            )
        auth_conf.update(
            {
                "domain_controller": "wsgidav.dc.pam_dc.PAMDomainController",
                "accept_basic": True,
                "accept_digest": False,
                "default_to_digest": False,
            }
        )
        config["pam_dc"] = {"service": "login"}
    # print(config)

    # if cli_opts.get("reload"):
    #     print("Installing paste.reloader.", file=sys.stderr)
    #     from paste import reloader  # @UnresolvedImport

    #     reloader.install()
    #     if config_file:
    #         # Add config file changes
    #         reloader.watch_file(config_file)
    #     # import pydevd
    #     # pydevd.settrace()

    if config["suppress_version_info"]:
        util.public_wsgidav_info = "WsgiDAV"
        util.public_python_info = f"Python/{sys.version_info[0]}"

    return cli_opts, config


def _run_uvicorn(app, config):
    """Run WsgiDAV using Uvicorn (https://www.uvicorn.org)."""
    try:
        import uvicorn
    except ImportError:
        _logger.exception("Could not import Uvicorn (https://www.uvicorn.org).")
        _logger.error("Try `pip install uvicorn`.")
        return False

    info = _get_common_info(config)

    # See https://www.uvicorn.org/settings/
    server_args = {
        "interface": "wsgi",
        "host": config["host"],
        "port": config["port"],
        # TODO: see _run_cheroot()
    }

    if info["use_ssl"]:
        server_args.update(
            {
                "ssl_keyfile": info["ssl_pk"],
                "ssl_certfile": info["ssl_cert"],
                "ssl_ca_certs": info["ssl_chain"],
                # "ssl_keyfile_password": ssl_keyfile_password
                # "ssl_version": ssl_version
                # "ssl_cert_reqs": ssl_cert_reqs
                # "ssl_ciphers": ssl_ciphers
            }
        )

    # Override or add custom args
    custom_args = util.get_dict_value(config, "server_args", as_dict=True)
    server_args.update(custom_args)

    version = f"uvicorn/{uvicorn.__version__}"
    version = f"{util.public_wsgidav_info} {version} {util.public_python_info}"
    _logger.info(f"Running {version} ...")

    uvicorn.run(app, **server_args)


def run():
    cli_opts, config = _init_config()
    # util.init_logging(config) # now handled in constructor:
    config["logging"]["enable"] = True
    info = _get_common_info(config)
    app = AsgiDavApp(config)

    if not use_lxml and config["verbose"] >= 3:
        _logger.warning(
            "Could not import lxml: using xml instead (up to 10% slower). "
            "Consider `pip install lxml`(see https://pypi.python.org/pypi/lxml)."
        )

    if cli_opts["browse"]:
        BROWSE_DELAY = 2.0

        def _worker():
            url = info["url"]
            url = url.replace("0.0.0.0", "127.0.0.1")
            _logger.info(f"Starting browser on {url} ...")
            webbrowser.open(url)

        Timer(BROWSE_DELAY, _worker).start()

    _run_uvicorn(app, config)

    return


if __name__ == "__main__":
    # Just in case...
    from multiprocessing import freeze_support

    freeze_support()

    run()
