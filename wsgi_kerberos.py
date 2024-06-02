'''
WSGI Kerberos Authentication Middleware

Add Kerberos/GSSAPI Negotiate Authentication support to any WSGI Application
'''
import base64
import errno
import logging

import gssapi

_DEFAULT_READ_MAX = int(1e8)  # 100 MB
_CHUNK_SIZE = 1024 * 64       # Match Werkzeug: https://git.io/JtTiR
_LOG = logging.getLogger(__name__)

# Quoting https://specs.openstack.org/openstack/api-wg/guidelines/http/methods.html:
# HTTP request bodies are theoretically allowed for all methods except TRACE,
# however they are not commonly used except in PUT, POST and PATCH. Because of
# this, they may not be supported properly by some client frameworks, and you
# should not allow request bodies for GET, DELETE, TRACE, OPTIONS and HEAD methods.
_NEVER_READ_METHODS = frozenset({'GET', 'DELETE', 'TRACE', 'OPTIONS', 'HEAD'})


class KerberosAuthMiddleware:
    '''
    WSGI Middleware providing Kerberos Authentication

    :param app: WSGI Application
    :param hostname: Force the server to only accept requests for the specified
        hostname. If not specified, clients can access the service by any name
        in the keytab.
    :type hostname: str
    :param unauthorized: 401 Response text or text/content-type tuple
    :type unauthorized: tuple
    :param forbidden: 403 Response text or text/content-type tuple
    :type forbidden: tuple
    :param auth_required_callback: predicate accepting the WSGI environ
        for a request returning whether the request should be authenticated
    :type auth_required_callback: callable
    :param read_max_on_auth_fail: When a request could not be authenticated,
        read and discard up to this many bytes of the request. This may help
        naively-written clients that send large request bodies which they
        expect to be consumed before first confirming that the request was
        authenticated successfully. Pass 0 to disable this if you don't want to
        waste resources to potentially accommodate such clients. Pass float('inf')
        to read an unlimited number of bytes. Beware that the more the server
        is willing to read, the more vulnerable it becomes to denial-of-service
        attacks.
    :type read_max_on_auth_fail: int
    :param logger: logging provider
    :type logger: logging.Logger
    '''

    def __init__(
        self,
        app,
        hostname='',
        unauthorized=(b"Unauthorized", "text/plain"),
        forbidden=(b"Forbidden", "text/plain"),
        auth_required_callback=lambda _: True,
        read_max_on_auth_fail=_DEFAULT_READ_MAX,
        logger=_LOG,
    ):
        self.application = app               # WSGI Application
        self.unauthorized = unauthorized     # 401 response text/content-type
        self.forbidden = forbidden           # 403 response text/content-type
        self.auth_required_callback = auth_required_callback
        self.read_max_on_auth_fail = read_max_on_auth_fail
        self.logger = logger

        self.service = None
        if hostname:
            try:
                # TODO: support different GSSAPI backends other than Kerberos
                self.service = gssapi.Name(f"HTTP/{hostname}@").canonicalize(gssapi.MechType.kerberos)
            except gssapi.GSSError as exc:
                self.logger.warning('Failed to create GSSAPI service credential name "HTTP/%s@" for Kerberos mechanism: %s', hostname, exc)
            else:
                self.logger.info('KerberosAuthMiddleware is identifying as %s', self.service)

    def _unauthorized(self, environ, start_response, token='Negotiate'):
        '''
        Send a 401 Unauthorized response
        '''
        headers = [
            ('content-type', self.unauthorized[1]),
            ('content-length', str(len(self.unauthorized[0]))),
            ('WWW-Authenticate', token),
        ]
        self._consume_request(environ)
        start_response('401 Unauthorized', headers)
        return [self.unauthorized[0]]

    def _forbidden(self, environ, start_response):
        '''
        Send a 403 Forbidden response
        '''
        headers = [
            ('content-type', self.forbidden[1]),
            ('content-length', str(len(self.forbidden[0])))
        ]
        self._consume_request(environ)
        start_response('403 Forbidden', headers)
        return [self.forbidden[0]]

    def _authenticate(self, client_token):
        '''
        Validate the client token

        Return the authenticated users principal and a token suitable to
        provide mutual authentication to the client.
        '''

        # TODO: re-acquire credentials only when the credentials expire instead of every request
        try:
            gssapi_creds = gssapi.Credentials(usage="accept", name=self.service)
        except Exception:
            self.logger.exception(
                "GSSAPI error: Failed to obtain kerberos credentials from the system keytab!"
            )
            return None, None

        try:
            gssapi_ctx = gssapi.SecurityContext(creds=gssapi_creds, usage="accept")
        except Exception:
            self.logger.exception(
                "GSSAPI error: Failed to create a GSSAPI security context for the given kerberos credentials!"
            )
            return None, None

        try:
            gssapi_token = gssapi_ctx.step(base64.b64decode(client_token, validate=True))
        except Exception:
            self.logger.exception(
                "GSSAPI error: Failed to perform GSSAPI negotation!"
            )
            return None, None

        server_token = base64.b64encode(gssapi_token).decode()
        user = str(gssapi_ctx.initiator_name)
        return server_token, user

    def _consume_request(self, environ, chunk_size=_CHUNK_SIZE):
        """
        Consume and discard up to *read_max_on_auth_fail* bytes of the request.

        This avoids problems that some clients have when the server does not
        download the entire request body before sending the response, such as
        for requests that could not be authenticated.

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
        """
        if (
            self.read_max_on_auth_fail == 0
        ):  # Short-circuit early when user opts out of this.
            return
        if environ["REQUEST_METHOD"] in _NEVER_READ_METHODS:
            return
        if environ.get("HTTP_EXPECT") == "100-continue":
            return
        try:
            body = environ.get("wsgi.input")
            if hasattr(body, "closed") and body.closed:
                return

            content_length = environ.get("CONTENT_LENGTH", "")
            if not content_length:
                self.logger.info("No Content-Length -> skipping _consume_request")
                return
            content_length = int(content_length)
            if content_length > self.read_max_on_auth_fail:
                # Server is not willing to read such a large request body, but
                # reading anything less does not help naively-written clients.
                self.logger.warning(
                    "Content-Length (%d) exceeds read_max_on_auth_fail (%s) -> not consuming"
                    " request body; client may get a connection error. Enabling"
                    " preemptive authentication on the client may avoid this."
                    " You can also pass a higher value of `read_max_on_auth_fail`"
                    " to KerberosAuthMiddleware.",
                    content_length,
                    self.read_max_on_auth_fail,
                )
                return
            # Try to receive all of the data. Keep retrying until we get an error
            # which indicates that we can't retry. Eat errors. The client will just
            # have to deal with a possible Broken Pipe -- we tried.
            remaining = content_length
            while remaining > 0:
                to_read = min(chunk_size, remaining)
                try:
                    read = len(body.read(to_read))
                except OSError as err:
                    if err.errno != errno.EAGAIN:
                        raise
                else:
                    if read != to_read:
                        break
                    remaining -= read
        except Exception as exc:
            self.logger.info("_consume_request suppressed: %s", exc)

    def __call__(self, environ, start_response):
        '''
        Authenticate the client, and on success invoke the WSGI application.
        Include a token in the response headers that can be used to
        authenticate the server to the client.
        '''
        # If we don't need to authenticate the request, don't immediately
        # bypass authentication, but rather just remember this for now.
        # This way, if auth is not required, but the client provides valid
        # auth anyway, we still tell the application who made the request.
        auth_required = self.auth_required_callback(environ)

        def _40x_resp_if_auth_required(error_resp, **kw):
            if auth_required:
                return error_resp(environ, start_response, **kw)
            return self.application(environ, start_response)

        authorization = environ.get('HTTP_AUTHORIZATION')
        # If we have no 'Authorization' header...
        if authorization is None:
            return _40x_resp_if_auth_required(self._unauthorized)

        # We have an Authorization header -> should start with "negotiate".
        parsed = authorization.split(None, 1)
        if len(parsed) < 2 or parsed[0].lower() != 'negotiate':
            self.logger.info("Authorization header did not start with 'negotiate'")
            return _40x_resp_if_auth_required(self._unauthorized)

        # Extract the client's token and attempt to authenticate with it.
        client_token = parsed[1]
        server_token, user = self._authenticate(client_token)

        # If we get a server_token and a user, call the application, add our
        # token, and return the response for mutual authentication
        if server_token and user:
            # Add the user to the environment for the application to use it,
            # call the application, add the token to the response, and return
            # it
            environ['REMOTE_USER'] = user

            def custom_start_response(status, headers, exc_info=None):
                headers.append(('WWW-Authenticate', 'Negotiate ' + server_token))
                return start_response(status, headers, exc_info)
            return self.application(environ, custom_start_response)
        # If we get a a user, but no token, call the application but don't
        # provide mutual authentication.
        elif user:
            environ['REMOTE_USER'] = user
            return self.application(environ, start_response)
        elif server_token:
            # If we got a token, but no user, return a 401 with the token
            return _40x_resp_if_auth_required(
                self._unauthorized, token="Negotiate " + server_token)
        else:
            # Otherwise, return a 403.
            return _40x_resp_if_auth_required(self._forbidden)
