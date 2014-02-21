'''
WSGI Kerberos Authentication Middleware

Add Kerberos/GSSAPI Negotiate Authentication support to any WSGI Application
'''
import kerberos
import logging
import os
import socket

LOG = logging.getLogger(__name__)
LOG.addHandler(logging.NullHandler())


def _consume_request(environ):
    '''
    Consume and discard all of the data on the request.

    This avoids problems that some clients have when they get an unexpected
    and premature close from the server.

    RFC2616: If an origin server receives a request that does not include an
    Expect request-header field with the "100-continue" expectation, the
    request includes a request body, and the server responds with a final
    status code before reading the entire request body from the transport
    connection, then the server SHOULD NOT CLOSE the transport connection until
    it has read the entire request, or until the client closes the connection.
    Otherwise, the client might not reliably receive the response message.
    However, this requirement is not be construed as preventing a server from
    defending itself against denial-of-service attacks, or from badly broken
    client implementations.
    '''
    try:
        sock = environ.get('wsgi.input')
        if hasattr(sock, 'closed') and sock.closed:
            return
        # Figure out how much content is available for us to consume.
        expected = int(environ.get('CONTENT_LENGTH', '0'))

        # Try to receive all of the data. Keep retrying until we get an error
        # which indicates that we can't retry. Eat errors. The client will just
        # have to deal with a possible Broken Pipe -- we tried.
        received = 0
        while received < expected:
            try:
                received += len(sock.read(expected - received))
            except socket.error as err:
                if err.errno != errno.EAGAIN:
                    break
    except (KeyError, ValueError):
        pass


class KerberosAuthMiddleware(object):
    '''
    WSGI Middleware providing Kerberos Authentication

    If no hostname is provided, the name returned by socket.gethostname() will
    be used.

    :param app: WSGI Application
    :param hostname: Hostname for kerberos name canonicalization
    :type hostname: str
    :param unauthorized: 401 Response text or text/content-type tuple
    :type unauthorized: str or tuple
    :param forbidden: 403 Response text or text/content-type tuple
    :type forbidden: str or tuple
    '''

    def __init__(self, app, hostname=None, unauthorized=None, forbidden=None,
                 auth_required_callback=None):
        if hostname is None:
            hostname = socket.gethostname()

        if unauthorized is None:
            unauthorized = ('Unauthorized', 'text/plain')
        elif isinstance(unauthorized, basestring):
            unauthorized = (unauthorized, 'text/plain')

        if forbidden is None:
            forbidden = ('Forbidden', 'text/plain')
        elif isinstance(forbidden, basestring):
            forbidden = (forbidden, 'text/plain')

        if auth_required_callback is None:
            auth_required_callback = lambda x: True

        self.application = app               # WSGI Application
        self.service = 'HTTP@%s' % hostname  # GSS Service
        self.unauthorized = unauthorized     # 401 response text/content-type
        self.forbidden = forbidden           # 403 response text/content-type
        self.auth_required_callback = auth_required_callback

        if 'KRB5_KTNAME' in os.environ:
            try:
                principal = kerberos.getServerPrincipalDetails('HTTP',
                                                               hostname)
            except kerberos.KrbError as exc:
                LOG.warn('KerberosAuthMiddleware: %s' % exc.message[0])
            else:
                LOG.debug('KerberosAuthMiddleware is identifying as %s' %
                          principal)
        else:
            LOG.warn('KerberosAuthMiddleware: set KRB5_KTNAME to your keytab '
                     'file')

    def _unauthorized(self, environ, start_response, token=None):
        '''
        Send a 401 Unauthorized response
        '''
        headers = [('content-type', self.unauthorized[1])]
        if token:
            headers.append(('WWW-Authenticate', token))
        else:
            headers.append( ('WWW-Authenticate', 'Negotiate'))
        _consume_request(environ)
        start_response('401 Unauthorized', headers)
        return [self.unauthorized[0]]

    def _forbidden(self, environ, start_response):
        '''
        Send a 403 Forbidden response
        '''
        headers = [('content-type', self.forbidden[1])]
        _consume_request(environ)
        start_response('403 Forbidden', headers)
        return [self.forbidden[0]]

    def _authenticate(self, client_token):
        '''
        Validate the client token

        Return the authenticated users principal and a token suitable to
        provide mutual authentication to the client.
        '''
        state = None
        server_token = None
        user = None
        try:
            rc, state = kerberos.authGSSServerInit(self.service)
            if rc == kerberos.AUTH_GSS_COMPLETE:
                rc = kerberos.authGSSServerStep(state, client_token)
                if rc == kerberos.AUTH_GSS_COMPLETE:
                    server_token = kerberos.authGSSServerResponse(state)
                    user = kerberos.authGSSServerUserName(state)
                elif rc == kerberos.AUTH_GSS_CONTINUE:
                    server_token = kerberos.authGSSServerResponse(state)
        except kerberos.GSSError:
            pass
        finally:
            if state:
                kerberos.authGSSServerClean(state)
        return server_token, user


    def __call__(self, environ, start_response):
        '''
        Authenticate the client, and on success invoke the WSGI application.
        Include a token in the response headers that can be used to
        authenticate the server to the client.
        '''
        # If we don't need to authenticate the request, shortcut the whole
        # process.
        if not self.auth_required_callback(environ):
            return self.application(environ, start_response)

        authorization = environ.get('HTTP_AUTHORIZATION')
        # If we have no 'Authorization' header, return a 401.
        if authorization is None:
            return self._unauthorized(environ, start_response)

        # If we have an 'Authorization' header, extract the client's token and
        # attempt to authenticate with it.
        client_token = ''.join(authorization.split()[1:])
        server_token, user = self._authenticate(client_token)

        # If we get a server_token and a user, call the application, add our
        # token, and return the response for mutual authentication
        if server_token and user:
            # Add the user to the environment for the application to use it,
            # call the application, add the token to the response, and return
            # it
            environ['REMOTE_USER'] = user
            def custom_start_response(status, headers, exc_info=None):
                headers.append(('WWW-Authenticate', ' '.join(['negotiate',
                                                              server_token])))
                return start_response(status, headers, exc_info)
            return self.application(environ, custom_start_response)
        elif server_token:
            # If we got a token, but no user, return a 401 with the token
            return self._unauthorized(start_response, server_token)
        else:
            # Otherwise, return a 403.
            return self._forbidden(environ, start_response)
