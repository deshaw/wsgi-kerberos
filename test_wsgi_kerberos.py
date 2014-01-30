from wsgi_kerberos import KerberosAuthMiddleware
from webtest import TestApp
import kerberos
import mock
import unittest

def index(environ, start_response):
    start_response('200 OK', [('Content-Type', 'text/plain')])
    return ['Hello %s' % environ.get('REMOTE_USER', 'ANONYMOUS')]


class BasicAppTestCase(unittest.TestCase):
    @mock.patch('kerberos.authGSSServerInit')
    @mock.patch('kerberos.authGSSServerStep')
    @mock.patch('kerberos.authGSSServerResponse')
    @mock.patch('kerberos.authGSSServerUserName')
    @mock.patch('kerberos.authGSSServerClean')
    def test_authentication_not_required(self, clean, name, response, step, init):
        '''
        Ensure that when a users auth_required_callback returns False,
        authentication is not performed.

        '''
        false = lambda x: False
        app = TestApp(KerberosAuthMiddleware(index,
                                             hostname='example.org',
                                             auth_required_callback=false))
        r = app.get('/', expect_errors=False)
        self.assertEqual(r.status, '200 OK')
        self.assertEqual(r.status_int, 200)
        self.assertEqual(r.body, 'Hello ANONYMOUS')
        self.assertEqual(r.headers.get('WWW-Authenticate'), None)
        self.assertEqual(r.headers['content-type'], 'text/plain')

        self.assertEqual(init.mock_calls, [])
        self.assertEqual(step.mock_calls, [])
        self.assertEqual(name.mock_calls, [])
        self.assertEqual(response.mock_calls, [])
        self.assertEqual(clean.mock_calls, [])

    def test_unauthorized(self):
        '''
        Ensure that when the client does not send an authorization token, they
        receive a 401 Unauthorized response which includes a www-authenticate
        header field which indicates the server supports Negotiate
        authentication.
        '''
        app = TestApp(KerberosAuthMiddleware(index, hostname='example.org'))

        r = app.get('/', expect_errors=True)

        self.assertEqual(r.status, '401 Unauthorized')
        self.assertEqual(r.status_int, 401)
        self.assertEqual(r.body, 'Unauthorized')
        self.assertEqual(r.headers['www-authenticate'], 'Negotiate')
        self.assertEqual(r.headers['content-type'], 'text/plain')

    def test_unauthorized_custom(self):
        '''
        Ensure that when the client does not send an authorization token, they
        receive a 401 Unauthorized response which includes a www-authenticate
        header field which indicates the server supports Negotiate
        authentication. If configured, they should also receive customized
        content.
        '''
        app = TestApp(KerberosAuthMiddleware(index,
                                             hostname='example.org',
                                             unauthorized='CUSTOM'))

        r = app.get('/', expect_errors=True)

        self.assertEqual(r.status, '401 Unauthorized')
        self.assertEqual(r.status_int, 401)
        self.assertEqual(r.body, 'CUSTOM')
        self.assertEqual(r.headers['www-authenticate'], 'Negotiate')
        self.assertEqual(r.headers['content-type'], 'text/plain')

    def test_unauthorized_custom_content_type(self):
        '''
        Ensure that when the client does not send an authorization token, they
        receive a 401 Unauthorized response which includes a www-authenticate
        header field which indicates the server supports Negotiate
        authentication. If configured, they should also receive customized
        content and content type.
        '''
        app = TestApp(KerberosAuthMiddleware(index,
                                             hostname='example.org',
                                             unauthorized=('CUSTOM',
                                                           'text/html')))

        r = app.get('/', expect_errors=True)

        self.assertEqual(r.status, '401 Unauthorized')
        self.assertEqual(r.status_int, 401)
        self.assertEqual(r.body, 'CUSTOM')
        self.assertEqual(r.headers['www-authenticate'], 'Negotiate')
        self.assertEqual(r.headers['content-type'], 'text/html')

    @mock.patch('kerberos.authGSSServerInit')
    @mock.patch('kerberos.authGSSServerStep')
    @mock.patch('kerberos.authGSSServerResponse')
    @mock.patch('kerberos.authGSSServerUserName')
    @mock.patch('kerberos.authGSSServerClean')
    def test_authorized(self, clean, name, response, step, init):
        '''
        Ensure that when the client sends an correct authorization token,
        they receive a 200 OK response and the user principal is extracted and
        passed on to the routed method.
        '''
        state = object()
        init.return_value = (kerberos.AUTH_GSS_COMPLETE, state)
        step.return_value = kerberos.AUTH_GSS_COMPLETE
        name.return_value = "user@EXAMPLE.ORG"
        response.return_value = "STOKEN"
        app = TestApp(KerberosAuthMiddleware(index, hostname='example.org'))

        r = app.get('/', headers={'Authorization': 'Negotiate CTOKEN'})

        self.assertEqual(r.status, '200 OK')
        self.assertEqual(r.status_int, 200)
        self.assertEqual(r.body, 'Hello user@EXAMPLE.ORG')
        self.assertEqual(r.headers['WWW-Authenticate'], 'STOKEN')
        self.assertEqual(r.headers['content-type'], 'text/plain')

        self.assertEqual(init.mock_calls, [mock.call('HTTP@example.org')])
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
        app = TestApp(KerberosAuthMiddleware(index, hostname='example.org'))

        r = app.get('/',
                    headers={'Authorization': 'Negotiate CTOKEN'},
                    expect_errors=True)

        self.assertEqual(r.status, '403 Forbidden')
        self.assertEqual(r.status_int, 403)
        self.assertEqual(r.body, 'Forbidden')
        self.assertEqual(r.headers['content-type'], 'text/plain')

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
    def test_forbidden_custom(self, clean, name, response, step, init):
        '''
        Ensure that when the client sends an incorrect authorization token,
        they receive a 403 Forbidden response. If configured, they should
        receive customized content.
        '''
        state = object()
        init.return_value = (kerberos.AUTH_GSS_COMPLETE, state)
        step.side_effect = kerberos.GSSError("FAILURE")
        app = TestApp(KerberosAuthMiddleware(index,
                                             hostname='example.org',
                                             forbidden='CUSTOM'))

        r = app.get('/',
                    headers={'Authorization': 'Negotiate CTOKEN'},
                    expect_errors=True)

        self.assertEqual(r.status, '403 Forbidden')
        self.assertEqual(r.status_int, 403)
        self.assertEqual(r.body, 'CUSTOM')
        self.assertEqual(r.headers['content-type'], 'text/plain')

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
    def test_forbidden_custom_content_type(self, clean, name, response, step, init):
        '''
        Ensure that when the client sends an incorrect authorization token,
        they receive a 403 Forbidden response. If configured, they should
        receive customized content and content-type.
        '''
        state = object()
        init.return_value = (kerberos.AUTH_GSS_COMPLETE, state)
        step.side_effect = kerberos.GSSError("FAILURE")
        app = TestApp(KerberosAuthMiddleware(index,
                                             hostname='example.org',
                                             forbidden=('CUSTOM',
                                                        'text/html')))

        r = app.get('/',
                    headers={'Authorization': 'Negotiate CTOKEN'},
                    expect_errors=True)

        self.assertEqual(r.status, '403 Forbidden')
        self.assertEqual(r.status_int, 403)
        self.assertEqual(r.body, 'CUSTOM')
        self.assertEqual(r.headers['content-type'], 'text/html')

        self.assertEqual(init.mock_calls, [mock.call('HTTP@example.org')])
        self.assertEqual(step.mock_calls, [mock.call(state, 'CTOKEN')])
        self.assertEqual(name.mock_calls, [])
        self.assertEqual(response.mock_calls, [])
        self.assertEqual(clean.mock_calls, [mock.call(state)])

if __name__ == '__main__':
    unittest.main()
