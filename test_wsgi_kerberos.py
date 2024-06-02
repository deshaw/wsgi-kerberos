import base64
import copy
import os

import gssapi
import k5test
import requests
import requests_gssapi
from wsgi_intercept import add_wsgi_intercept, remove_wsgi_intercept, requests_intercept

from wsgi_kerberos import _DEFAULT_READ_MAX, KerberosAuthMiddleware

REALM = "EXAMPLE.ORG"
HOSTNAME = REALM.lower()
TEST_PORT = 8888
TEST_URL = f"http://{HOSTNAME}:{TEST_PORT}/"
USER1 = (f"user1@{REALM}", "pass1")
USER2 = (f"user2@{REALM}", "pass2")
HTTP_SERVICE = f"HTTP/{HOSTNAME}@{REALM}"


def index(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    response_body = f"Hello {environ.get('REMOTE_USER', 'ANONYMOUS')}"
    return [response_body.encode("utf-8")]


class CustomSpnegoAuth(requests_gssapi.HTTPSPNEGOAuth):
    def __init__(self, creds=None):
        super().__init__(
            target_name=gssapi.Name(HTTP_SERVICE).canonicalize(
                gssapi.MechType.kerberos
            ),
            creds=creds,
            opportunistic_auth=True,
        )


class BasicAppTestCase(k5test.KerberosTestCase):
    @classmethod
    def _init_env(cls):
        cls._saved_env = copy.deepcopy(os.environ)
        for k, v in cls.realm.env.items():
            os.environ[k] = v

    @classmethod
    def _restore_env(cls):
        for k in copy.deepcopy(os.environ):
            if k in cls._saved_env:
                os.environ[k] = cls._saved_env[k]
            else:
                del os.environ[k]

        cls._saved_env = None

    @classmethod
    def setUpClass(cls):
        cls.realm = k5test.realm.K5Realm(
            realm=REALM,
            create_user=False,
            get_creds=False,
            create_host=False,
        )
        cls.realm.addprinc(USER1[0], USER1[1])
        cls.realm.addprinc(USER2[0], USER2[1])
        cls.realm.addprinc(HTTP_SERVICE)
        # TODO: add test for the absence of the HTTP service principal in the realm
        cls.realm.extract_keytab(HTTP_SERVICE, cls.realm.keytab)
        requests_intercept.install()

        cls._init_env()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        requests_intercept.uninstall()

        cls._restore_env()

    def test_authentication_missing_but_not_required(self):
        """
        Ensure that when a user's auth_required_callback returns False,
        and the request is missing an auth token,
        authentication is not performed.
        """
        app = KerberosAuthMiddleware(
            index, hostname=HOSTNAME, auth_required_callback=lambda _: False
        )
        add_wsgi_intercept(HOSTNAME, TEST_PORT, lambda: app)
        r = requests.get(TEST_URL, auth=CustomSpnegoAuth())
        remove_wsgi_intercept()

        assert r.status_code == 200
        assert r.content == b"Hello ANONYMOUS"
        assert "WWW-Authenticate" not in r.headers

    def test_authentication_invalid_but_not_required(self):
        """
        Ensure that when a user's auth_required_callback returns False,
        and the request includes an invalid auth token,
        the invalid auth is ignored and the request
        is allowed through to the app.
        """
        app = KerberosAuthMiddleware(
            index, hostname=HOSTNAME, auth_required_callback=lambda _: False
        )
        add_wsgi_intercept(HOSTNAME, TEST_PORT, lambda: app)
        r = requests.get(TEST_URL, headers={"Authorization": "Negotiate BADTOKEN"})
        remove_wsgi_intercept()

        assert r.status_code == 200
        assert r.content == b"Hello ANONYMOUS"
        assert "WWW-Authenticate" not in r.headers

    def test_authentication_valid_but_not_required(self):
        """
        Ensure that when a users auth_required_callback returns False,
        but the request does include a valid auth token,
        the authenticated user is passed through to the app.
        """
        self.realm.kinit(USER1[0], USER1[1])
        app = KerberosAuthMiddleware(
            index, hostname=HOSTNAME, auth_required_callback=lambda _: False
        )

        user1_creds = gssapi.Credentials.acquire(
            name=gssapi.Name(USER1[0]).canonicalize(gssapi.MechType.kerberos),
            usage="initiate",
        )

        add_wsgi_intercept(HOSTNAME, TEST_PORT, lambda: app)
        r = requests.get(TEST_URL, auth=CustomSpnegoAuth(user1_creds.creds))
        remove_wsgi_intercept()

        assert r.status_code == 200
        assert r.content == f"Hello {USER1[0]}".encode()

        authenticate_header = r.headers['WWW-Authenticate'].split()
        assert authenticate_header[0].lower() == 'negotiate'
        assert isinstance(base64.b64decode(authenticate_header[1], validate=True), bytes)

    def test_unauthorized(self):
        """
        Ensure that when the client does not send an authorization token, they
        receive a 401 Unauthorized response which includes a www-authenticate
        header field which indicates the server supports Negotiate
        authentication.
        """
        app = KerberosAuthMiddleware(index)
        add_wsgi_intercept(HOSTNAME, TEST_PORT, lambda: app)
        r = requests.get(TEST_URL)
        remove_wsgi_intercept()

        assert r.status_code ==  401
        assert r.content == b"Unauthorized"
        assert r.headers["WWW-Authenticate"] == "Negotiate"
        assert r.headers["Content-Type"] == "text/plain"
        assert r.headers["Content-Length"] == str(len(r.content))

    def test_read_max_on_auth_fail(self):
        """
        KerberosAuthMiddleware's ``read_max_on_auth_fail`` should allow
        customizing reading of request bodies of unauthenticated requests.
        """
        body = "body of unauthenticated request"
        for read_max in (0, 5, 100, _DEFAULT_READ_MAX, float("inf")):
            with self.subTest(read_max=read_max):
                def wrap_app(environ, start_response):
                    resp = KerberosAuthMiddleware(
                        index, read_max_on_auth_fail=read_max
                    )(environ, start_response)

                    content_length = len(body)
                    expect_read = 0 if read_max < content_length else min(read_max, content_length)

                    assert environ["wsgi.input"].tell() == expect_read
                    return resp

                add_wsgi_intercept(HOSTNAME, TEST_PORT, lambda: wrap_app)
                requests.post(TEST_URL, data=body)
                remove_wsgi_intercept()

    def test_unauthorized_when_missing_negotiate(self):
        """
        Ensure that when the client sends an Authorization header that does
        not start with "Negotiate ", they receive a 401 Unauthorized response
        with a "WWW-Authenticate: Negotiate" header.
        """
        app = KerberosAuthMiddleware(index)
        add_wsgi_intercept(HOSTNAME, TEST_PORT, lambda: app)
        r = requests.get(TEST_URL, headers={"Authorization": "foo"})
        remove_wsgi_intercept()

        assert r.status_code ==  401
        assert r.content.startswith(b"Unauthorized")
        assert r.headers["WWW-Authenticate"].lower() == "negotiate"
        assert r.headers["Content-Type"] == "text/plain"
        assert r.headers["Content-Length"] == str(len(r.content))

    def test_unauthorized_custom(self):
        """
        Ensure that when the client does not send an authorization token, they
        receive a 401 Unauthorized response which includes a www-authenticate
        header field which indicates the server supports Negotiate
        authentication. If configured, they should also receive customized
        content.
        """
        app = KerberosAuthMiddleware(index, unauthorized=(b"CUSTOM", "text/plain"))
        add_wsgi_intercept(HOSTNAME, TEST_PORT, lambda: app)
        r = requests.get(TEST_URL)
        remove_wsgi_intercept()

        assert r.status_code == 401
        assert r.content == b"CUSTOM"
        assert r.headers["WWW-Authenticate"].lower() == "negotiate"
        assert r.headers["Content-Type"] == "text/plain"
        assert r.headers["Content-Length"] == str(len(r.content))

    def test_unauthorized_custom_content_type(self):
        """
        Ensure that when the client does not send an authorization token, they
        receive a 401 Unauthorized response which includes a www-authenticate
        header field which indicates the server supports Negotiate
        authentication. If configured, they should also receive customized
        content and content type.
        """
        app = KerberosAuthMiddleware(index, unauthorized=(b"401!", "text/html"))
        add_wsgi_intercept(HOSTNAME, TEST_PORT, lambda: app)
        r = requests.get(TEST_URL)
        remove_wsgi_intercept()

        assert r.status_code ==  401
        assert r.content ==  b"401!"
        assert r.headers["WWW-Authenticate"].lower() == "negotiate"
        assert r.headers["Content-Type"] == "text/html"
        assert r.headers["Content-Length"] == str(len(r.content))

    def test_authorized(self):
        """
        Ensure that when the client sends a correct authorization token,
        they receive a 200 OK response and the user principal is extracted and
        passed on to the routed method.
        """
        self.realm.kinit(USER1[0], USER1[1])
        user1_creds = gssapi.Credentials.acquire(
            name=gssapi.Name(USER1[0]).canonicalize(gssapi.MechType.kerberos),
            usage="initiate",
        )

        app = KerberosAuthMiddleware(index, hostname=HOSTNAME)
        add_wsgi_intercept(HOSTNAME, TEST_PORT, lambda: app)
        r = requests.get(TEST_URL, auth=CustomSpnegoAuth(user1_creds.creds))
        remove_wsgi_intercept()

        assert r.status_code == 200
        assert r.content == f"Hello {USER1[0]}".encode()

        authenticate_header = r.headers["WWW-Authenticate"].split()
        assert authenticate_header[0].lower() == "negotiate"
        assert isinstance(base64.b64decode(authenticate_header[1], validate=True), bytes)

    def test_forbidden(self):
        """
        Ensure that when the client sends an incorrect authorization token,
        they receive a 403 Forbidden response.
        """
        app = KerberosAuthMiddleware(index, hostname=HOSTNAME)
        add_wsgi_intercept(HOSTNAME, TEST_PORT, lambda: app)
        r = requests.get(TEST_URL, headers={"Authorization": "Negotiate BADTOKEN"})
        remove_wsgi_intercept()

        assert r.status_code == 403
        assert r.content == b"Forbidden"
        assert r.headers["content-type"] == "text/plain"
        assert r.headers["content-length"] == str(len(r.content))

    def test_forbidden_custom(self):
        """
        Ensure that when the client sends an incorrect authorization token,
        they receive a 403 Forbidden response. If configured, they should
        receive customized content.
        """
        app = KerberosAuthMiddleware(index, forbidden=(b"CUSTOM", "text/plain"))
        add_wsgi_intercept(HOSTNAME, TEST_PORT, lambda: app)
        r = requests.get(TEST_URL, headers={"Authorization": "Negotiate BADTOKEN"})
        remove_wsgi_intercept()

        assert r.status_code ==  403
        assert r.content ==  b"CUSTOM"
        assert r.headers["content-type"] ==  "text/plain"
        assert r.headers["content-length"] ==  str(len(r.content))

    def test_forbidden_custom_content_type(self):
        """
        Ensure that when the client sends an incorrect authorization token,
        they receive a 403 Forbidden response. If configured, they should
        receive customized content and content-type.
        """
        app = KerberosAuthMiddleware(index, forbidden=(b"CUSTOM", "text/html"))
        add_wsgi_intercept(HOSTNAME, TEST_PORT, lambda: app)
        r = requests.get(TEST_URL, headers={"Authorization": "Negotiate BADTOKEN"})
        remove_wsgi_intercept()

        assert r.status_code == 403
        assert r.content == b"CUSTOM"
        assert r.headers["content-type"] == "text/html"
        assert r.headers["content-length"] == str(len(r.content))
