from wsgi_kerberos import KerberosAuthMiddleware, ensure_bytestring, _DEFAULT_READ_MAX
from webtest import TestApp, TestRequest
import kerberos
import mock
import unittest


def index(environ, start_response):
    start_response('200 OK', [('Content-Type', 'text/plain')])
    response_body = 'Hello %s' % environ.get('REMOTE_USER', 'ANONYMOUS')
    return [ensure_bytestring(response_body)]


class BasicAppTestCase(unittest.TestCase):
    @mock.patch('kerberos.authGSSServerInit')
    @mock.patch('kerberos.authGSSServerStep')
    @mock.patch('kerberos.authGSSServerResponse')
    @mock.patch('kerberos.authGSSServerUserName')
    @mock.patch('kerberos.authGSSServerClean')
    def test_authentication_missing_but_not_required(self, clean, name, response, step, init):
        '''
        Ensure that when a user's auth_required_callback returns False,
        and the request is missing an auth token,
        authentication is not performed.
        '''
        false = lambda x: False
        app = TestApp(KerberosAuthMiddleware(index, auth_required_callback=false))
        r = app.get('/', expect_errors=False)
        self.assertEqual(r.status, '200 OK')
        self.assertEqual(r.status_int, 200)
        self.assertEqual(r.body, b'Hello ANONYMOUS')
        self.assertEqual(r.headers.get('WWW-Authenticate'), None)

        self.assertEqual(init.mock_calls, [])
        self.assertEqual(step.mock_calls, [])
        self.assertEqual(name.mock_calls, [])
        self.assertEqual(response.mock_calls, [])
        self.assertEqual(clean.mock_calls, [])

    @mock.patch('kerberos.authGSSServerInit')
    @mock.patch('kerberos.authGSSServerStep')
    @mock.patch('kerberos.authGSSServerResponse')
    @mock.patch('kerberos.authGSSServerUserName')
    @mock.patch('kerberos.authGSSServerClean')
    def test_authentication_invalid_but_not_required(self, clean, name, response, step, init):
        '''
        Ensure that when a user's auth_required_callback returns False,
        and the request includes an invalid auth token,
        the invalid auth is ignored and the request
        is allowed through to the app.
        '''
        state = object()
        init.return_value = (kerberos.AUTH_GSS_COMPLETE, state)
        step.side_effect = kerberos.GSSError("FAILURE")
        false = lambda x: False
        app = TestApp(KerberosAuthMiddleware(index,
                                             hostname='example.org',
                                             auth_required_callback=false))
        r = app.get('/', headers={'Authorization': 'Negotiate CTOKEN'})
        self.assertEqual(r.status, '200 OK')
        self.assertEqual(r.status_int, 200)
        self.assertEqual(r.body, b'Hello ANONYMOUS')
        self.assertEqual(r.headers.get('WWW-Authenticate'), None)

        self.assertEqual(init.mock_calls, [mock.call('HTTP@example.org')])
        self.assertEqual(step.mock_calls, [mock.call(state, 'CTOKEN')])
        self.assertEqual(name.mock_calls, [])
        self.assertEqual(response.mock_calls, [])
        self.assertEqual(clean.mock_calls, [mock.call(state)])

    @mock.patch('kerberos.authGSSServerInit')
    @mock.patch('kerberos.authGSSServerStep')
    @mock.patch('kerberos.authGSSServerResponse')
    @mock.patch('kerberos.authGSSServerUserName')
    @mock.patch('kerberos.authGSSServerClean')
    def test_authentication_valid_but_not_required(self, clean, name, response, step, init):
        '''
        Ensure that when a users auth_required_callback returns False,
        but the request does include a valid auth token,
        the authenticated user is passed through to the app.
        '''
        state = object()
        init.return_value = (kerberos.AUTH_GSS_COMPLETE, state)
        step.return_value = kerberos.AUTH_GSS_COMPLETE
        name.return_value = "user@EXAMPLE.ORG"
        response.return_value = "STOKEN"
        false = lambda x: False
        app = TestApp(KerberosAuthMiddleware(index,
                                             hostname='example.org',
                                             auth_required_callback=false))
        r = app.get('/', headers={'Authorization': 'Negotiate CTOKEN'})
        self.assertEqual(r.status, '200 OK')
        self.assertEqual(r.status_int, 200)
        self.assertEqual(r.body, b'Hello user@EXAMPLE.ORG')
        self.assertEqual(r.headers.get('WWW-Authenticate'), 'negotiate STOKEN')

        self.assertEqual(init.mock_calls, [mock.call('HTTP@example.org')])
        self.assertEqual(step.mock_calls, [mock.call(state, 'CTOKEN')])
        self.assertEqual(name.mock_calls, [mock.call(state)])
        self.assertEqual(response.mock_calls, [mock.call(state)])
        self.assertEqual(clean.mock_calls, [mock.call(state)])

    def test_unauthorized(self):
        '''
        Ensure that when the client does not send an authorization token, they
        receive a 401 Unauthorized response which includes a www-authenticate
        header field which indicates the server supports Negotiate
        authentication.
        '''
        app = TestApp(KerberosAuthMiddleware(index))

        r = app.get('/', expect_errors=True)

        self.assertEqual(r.status, '401 Unauthorized')
        self.assertEqual(r.status_int, 401)
        self.assertEqual(r.body, b'Unauthorized')
        self.assertEqual(r.headers['www-authenticate'], 'Negotiate')
        self.assertEqual(r.headers['content-type'], 'text/plain')
        self.assertEqual(r.headers['content-length'], str(len(r.body)))

    def test_read_max_on_auth_fail(self):
        '''
        KerberosAuthMiddleware's ``read_max_on_auth_fail`` should allow
        customizing reading of request bodies of unauthenticated requests.
        '''
        body = b'body of unauthenticated request'
        for read_max in (0, 5, 100, _DEFAULT_READ_MAX, float('inf')):
            # When we drop Py2, we can use `with self.subTest(read_max=read_max):` here.
            app = TestApp(KerberosAuthMiddleware(index, read_max_on_auth_fail=read_max))
            req = TestRequest.blank('/', method='POST', body=body)
            resp = app.do_request(req, status=401)
            if read_max < len(body):
                expect_read = 0
            else:
                expect_read = min(read_max, len(body))
            self.assertEqual(req.body_file.input.tell(), expect_read)

    def test_unauthorized_when_missing_negotiate(self):
        '''
        Ensure that when the client sends an Authorization header that does
        not start with "Negotiate ", they receive a 401 Unauthorized response
        with a "WWW-Authenticate: Negotiate" header.
        '''
        app = TestApp(KerberosAuthMiddleware(index))

        r = app.get('/', headers={'Authorization': 'foo'}, expect_errors=True)

        self.assertEqual(r.status, '401 Unauthorized')
        self.assertEqual(r.status_int, 401)
        self.assertTrue(r.body.startswith(b'Unauthorized'))
        self.assertEqual(r.headers['www-authenticate'], 'Negotiate')
        self.assertEqual(r.headers['content-type'], 'text/plain')
        self.assertEqual(r.headers['content-length'], str(len(r.body)))

    def test_unauthorized_custom(self):
        '''
        Ensure that when the client does not send an authorization token, they
        receive a 401 Unauthorized response which includes a www-authenticate
        header field which indicates the server supports Negotiate
        authentication. If configured, they should also receive customized
        content.
        '''
        app = TestApp(KerberosAuthMiddleware(index, unauthorized='CUSTOM'))

        r = app.get('/', expect_errors=True)

        self.assertEqual(r.status, '401 Unauthorized')
        self.assertEqual(r.status_int, 401)
        self.assertEqual(r.body, b'CUSTOM')
        self.assertEqual(r.headers['www-authenticate'], 'Negotiate')
        self.assertEqual(r.headers['content-type'], 'text/plain')
        self.assertEqual(r.headers['content-length'], str(len(r.body)))

    def test_unauthorized_custom_content_type(self):
        '''
        Ensure that when the client does not send an authorization token, they
        receive a 401 Unauthorized response which includes a www-authenticate
        header field which indicates the server supports Negotiate
        authentication. If configured, they should also receive customized
        content and content type.
        '''
        app = TestApp(KerberosAuthMiddleware(index, unauthorized=('401!', 'text/html')))

        r = app.get('/', expect_errors=True)

        self.assertEqual(r.status, '401 Unauthorized')
        self.assertEqual(r.status_int, 401)
        self.assertEqual(r.body, b'401!')
        self.assertEqual(r.headers['www-authenticate'], 'Negotiate')
        self.assertEqual(r.headers['content-type'], 'text/html')
        self.assertEqual(r.headers['content-length'], str(len(r.body)))

    @mock.patch('kerberos.authGSSServerInit')
    @mock.patch('kerberos.authGSSServerStep')
    @mock.patch('kerberos.authGSSServerResponse')
    @mock.patch('kerberos.authGSSServerUserName')
    @mock.patch('kerberos.authGSSServerClean')
    def test_authorized(self, clean, name, response, step, init):
        '''
        Ensure that when the client sends a correct authorization token,
        they receive a 200 OK response and the user principal is extracted and
        passed on to the routed method.
        '''
        state = object()
        init.return_value = (kerberos.AUTH_GSS_COMPLETE, state)
        step.return_value = kerberos.AUTH_GSS_COMPLETE
        name.return_value = "user@EXAMPLE.ORG"
        response.return_value = "STOKEN"
        app = TestApp(KerberosAuthMiddleware(index))

        r = app.get('/', headers={'Authorization': 'Negotiate CTOKEN'})

        self.assertEqual(r.status, '200 OK')
        self.assertEqual(r.status_int, 200)
        self.assertEqual(r.body, b'Hello user@EXAMPLE.ORG')
        self.assertEqual(r.headers['WWW-Authenticate'], 'negotiate STOKEN')

        self.assertEqual(init.mock_calls, [mock.call('')])
        self.assertEqual(step.mock_calls, [mock.call(state, 'CTOKEN')])
        self.assertEqual(name.mock_calls, [mock.call(state)])
        self.assertEqual(response.mock_calls, [mock.call(state)])
        self.assertEqual(clean.mock_calls, [mock.call(state)])

    @mock.patch('kerberos.authGSSServerInit')
    @mock.patch('kerberos.authGSSServerStep')
    @mock.patch('kerberos.authGSSServerResponse')
    @mock.patch('kerberos.authGSSServerUserName')
    @mock.patch('kerberos.authGSSServerClean')
    def test_forbidden(self, clean, name, response, step, init):
        '''
        Ensure that when the client sends an incorrect authorization token,
        they receive a 403 Forbidden response.
        '''
        state = object()
        init.return_value = (kerberos.AUTH_GSS_COMPLETE, state)
        step.side_effect = kerberos.GSSError("FAILURE")
        app = TestApp(KerberosAuthMiddleware(index))

        r = app.get('/',
                    headers={'Authorization': 'Negotiate CTOKEN'},
                    expect_errors=True)

        self.assertEqual(r.status, '403 Forbidden')
        self.assertEqual(r.status_int, 403)
        self.assertEqual(r.body, b'Forbidden')
        self.assertEqual(r.headers['content-type'], 'text/plain')
        self.assertEqual(r.headers['content-length'], str(len(r.body)))

        self.assertEqual(init.mock_calls, [mock.call('')])
        self.assertEqual(step.mock_calls, [mock.call(state, 'CTOKEN')])
        self.assertEqual(name.mock_calls, [])
        self.assertEqual(response.mock_calls, [])
        self.assertEqual(clean.mock_calls, [mock.call(state)])

    @mock.patch('kerberos.authGSSServerInit')
    @mock.patch('kerberos.authGSSServerStep')
    @mock.patch('kerberos.authGSSServerResponse')
    @mock.patch('kerberos.authGSSServerUserName')
    @mock.patch('kerberos.authGSSServerClean')
    def test_forbidden_custom(self, clean, name, response, step, init):
        '''
        Ensure that when the client sends an incorrect authorization token,
        they receive a 403 Forbidden response. If configured, they should
        receive customized content.
        '''
        state = object()
        init.return_value = (kerberos.AUTH_GSS_COMPLETE, state)
        step.side_effect = kerberos.GSSError("FAILURE")
        app = TestApp(KerberosAuthMiddleware(index, forbidden='CUSTOM'))

        r = app.get('/',
                    headers={'Authorization': 'Negotiate CTOKEN'},
                    expect_errors=True)

        self.assertEqual(r.status, '403 Forbidden')
        self.assertEqual(r.status_int, 403)
        self.assertEqual(r.body, b'CUSTOM')
        self.assertEqual(r.headers['content-type'], 'text/plain')
        self.assertEqual(r.headers['content-length'], str(len(r.body)))

        self.assertEqual(init.mock_calls, [mock.call('')])
        self.assertEqual(step.mock_calls, [mock.call(state, 'CTOKEN')])
        self.assertEqual(name.mock_calls, [])
        self.assertEqual(response.mock_calls, [])
        self.assertEqual(clean.mock_calls, [mock.call(state)])

    @mock.patch('kerberos.authGSSServerInit')
    @mock.patch('kerberos.authGSSServerStep')
    @mock.patch('kerberos.authGSSServerResponse')
    @mock.patch('kerberos.authGSSServerUserName')
    @mock.patch('kerberos.authGSSServerClean')
    def test_forbidden_custom_content_type(self, clean, name, response, step, init):
        '''
        Ensure that when the client sends an incorrect authorization token,
        they receive a 403 Forbidden response. If configured, they should
        receive customized content and content-type.
        '''
        state = object()
        init.return_value = (kerberos.AUTH_GSS_COMPLETE, state)
        step.side_effect = kerberos.GSSError("FAILURE")
        app = TestApp(KerberosAuthMiddleware(index, forbidden=('CUSTOM', 'text/html')))

        r = app.get('/',
                    headers={'Authorization': 'Negotiate CTOKEN'},
                    expect_errors=True)

        self.assertEqual(r.status, '403 Forbidden')
        self.assertEqual(r.status_int, 403)
        self.assertEqual(r.body, b'CUSTOM')
        self.assertEqual(r.headers['content-type'], 'text/html')
        self.assertEqual(r.headers['content-length'], str(len(r.body)))

        self.assertEqual(init.mock_calls, [mock.call('')])
        self.assertEqual(step.mock_calls, [mock.call(state, 'CTOKEN')])
        self.assertEqual(name.mock_calls, [])
        self.assertEqual(response.mock_calls, [])
        self.assertEqual(clean.mock_calls, [mock.call(state)])


if __name__ == '__main__':
    unittest.main()
