# (c) 2009-2024 Martin Wendt and contributors; see WsgiDAV https://github.com/mar10/wsgidav
# Licensed under the MIT license:
# http://www.opensource.org/licenses/mit-license.php
"""
Unit test for wsgidav HTTP request functionality

This test suite uses webtest.TestApp to send fake requests to the WSGI
stack.

See http://webtest.readthedocs.org/en/latest/
    (successor of http://pythonpaste.org/testing-applications.html)
"""

import shutil
import unittest

import requests
import requests.auth

from AsgiDav import util
from tests.util import AsgiDavTestServer, create_test_folder

_test_server = None


# ========================================================================
# ServerTest
# ========================================================================


class ServerTest(unittest.TestCase):
    """Test wsgidav_app using paste.fixture."""

    def setUp(self):
        self.root_path = create_test_folder("wsgidav-test")

        global _test_server

        _test_server = AsgiDavTestServer(with_auth=False, with_ssl=False)
        _test_server.start()

    def tearDown(self):
        shutil.rmtree(self.root_path, ignore_errors=True)

        global _test_server

        if _test_server:
            _test_server.stop()

    def testPreconditions(self):
        """Environment must be set."""
        self.assertTrue(
            __debug__, "__debug__ must be True, otherwise asserts are ignored"
        )

    def testDirBrowser(self):
        """Server must respond to GET on a collection."""

        # Access collection (expect '200 Ok' with HTML response)
        res = requests.get("http://127.0.0.1:8080/")
        assert res.status_code == 200
        assert "WsgiDAV - Index of /" in res.text, "Could not list root share"
        assert "readme.txt" in res.text, "Fixture content"
        assert "Lotosblütenstengel (蓮花莖).docx" in res.text, "Encoded fixture content"

        # Access unmapped resource (expect '404 Not Found')
        res = requests.get("http://127.0.0.1:8080/not-existing-124/")
        assert res.status_code == 404

        res = requests.get("http://127.0.0.1:8080/subfolder/")
        assert res.status_code == 200

        res = requests.get(
            "http://127.0.0.1:8080/subfolder"
        )  # seems to follow redirects?
        assert res.status_code == 200

    def testGetPut(self):
        """Read and write file contents."""
        # Prepare file content
        data1 = b"this is a file\nwith two lines"
        data2 = b"this is another file\nwith three lines\nsee?"
        # Big file with 10 MB
        lines = []
        line = "." * (1000 - 6 - len("\n"))
        for i in range(10 * 1000):
            lines.append("%04i: %s\n" % (i, line))
        data3 = "".join(lines)
        data3 = util.to_bytes(data3)

        # Remove old test files
        requests.delete("http://127.0.0.1:8080/file1.txt")
        requests.delete("http://127.0.0.1:8080/file2.txt")
        requests.delete("http://127.0.0.1:8080/file3.txt")

        # Access unmapped resource (expect '404 Not Found')
        res = requests.delete("http://127.0.0.1:8080/file1.txt")
        assert res.status_code == 404
        res = requests.get("http://127.0.0.1:8080/file1.txt")
        assert res.status_code == 404

        # PUT a small file (expect '201 Created')
        res = requests.put(
            "http://127.0.0.1:8080/file1.txt",
            data=data1,
        )
        assert res.status_code == 201

        res = requests.get("http://127.0.0.1:8080/file1.txt")
        assert res.status_code == 200
        assert res.content == data1, "GET file content different from PUT"

        # PUT overwrites a small file (expect '204 No Content')
        res = requests.put("http://127.0.0.1:8080/file1.txt", data=data2)
        assert res.status_code == 204

        res = requests.get("http://127.0.0.1:8080/file1.txt")
        assert res.status_code == 200
        assert res.content == data2, "GET file content different from PUT"

        # PUT writes a big file (expect '201 Created')
        res = requests.put("http://127.0.0.1:8080/file2.txt", data=data3)
        assert res.status_code == 201

        res = requests.get("http://127.0.0.1:8080/file2.txt")
        assert res.status_code == 200
        assert res.content == data3, "GET file content different from PUT"

        # Request must not contain a body (expect '415 Media Type Not
        # Supported')
        res = requests.get(
            "http://127.0.0.1:8080/file1.txt",
            headers={"content-length": util.to_str(len(data1))},
            data=data1,
        )
        assert res.status_code == 415

        # Delete existing resource (expect '204 No Content')
        res = requests.delete("http://127.0.0.1:8080/file1.txt")
        assert res.status_code == 204
        # Get deleted resource (expect '404 Not Found')
        res = requests.get("http://127.0.0.1:8080/file1.txt")
        assert res.status_code == 404

        # PUT a small file (expect '201 Created')
        res = requests.put("http://127.0.0.1:8080/file1.txt", params=data1)
        assert res.status_code == 201

    # def testAuthentication(self):
    #     """Require login."""
    #     # Prepare file content (currently without authentication)
    #     data1 = b"this is a file\nwith two lines"
    #     app = self.app
    #     app.get("/file1.txt", status=404)  # not found
    #     app.put("/file1.txt", params=data1, status=201)
    #     app.get("/file1.txt", status=200)

    #     # Re-create test app with authentication
    #     wsgi_app = self._makeAsgiDavApp(self.root_path, True)
    #     app = self.app = webtest.TestApp(wsgi_app)

    #     # Anonymous access must fail (expect 401 Not Authorized)
    #     # Existing resource
    #     app.get("/file1.txt", status=401)
    #     # Non-existing resource
    #     app.get("/not_existing_file.txt", status=401)
    #     # Root container
    #     app.get("/", status=401)

    #     # Try basic access authentication
    #     user = "tester"
    #     password = "secret"
    #     creds = util.calc_base64(user + ":" + password)
    #     headers = {"Authorization": "Basic %s" % creds}
    #     # Existing resource
    #     app.get("/file1.txt", headers=headers, status=200)
    #     # Non-existing resource (expect 404 NotFound)
    #     app.get("/not_existing_file.txt", headers=headers, status=404)


if __name__ == "__main__":
    unittest.main()
