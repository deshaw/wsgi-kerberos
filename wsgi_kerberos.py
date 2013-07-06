import kerberos
import logging
import os
import socket

LOG = logging.getLogger(__name__)
LOG.addHandler(logging.NullHandler())


class KerberosAuthMiddleware(object):
    """WSGI Middleware providing Kerberos Authentication"""

    def __init__(self, application, hostname=None):
        if hostname is None:
            hostname = socket.gethostname()
        self.application = application       # WSGI Application
        self.service = "HTTP@%s" % hostname  # GSS Service hostname

        if 'KRB5_KTNAME' in os.environ:
            try:
                principal = kerberos.getServerPrincipalDetails('HTTP',
                                                               hostname)
            except kerberos.KrbError as exc:
                LOG.warn("KerberosAuthMiddleware: %s" % exc.message[0])
        else:
            LOG.warn("KerberosAuthMiddleware: set KRB5_KTNAME to your keytab "
                     "file")

    def _unauthorized(self, start_response, token=None):
        headers = [('content-type', 'text/plain')]
        if token:
            headers.append(('WWW-Authenticate', token))
        else:
            headers.append( ('WWW-Authenticate', 'Negotiate'))
        start_response('401 Unauthorized', headers)
        return ['Unauthorized',]

    def _forbidden(self, start_response, token):
        headers = [('content-type', 'text/plain')]
        start_response('403 Forbidden', headers)
        return ['Forbidden',]

    def _authenticate(self, client_token):
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
        authorization = environ.get('HTTP_AUTHORIZATION')
        # If we have no "Authorization" header, return a 401.
        if authorization is None:
            return self._unauthorized(start_response)

        # If we have an "Authorization" header, extract the client's token and
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
                headers.append(('WWW-Authenticate', server_token))
                return start_response(status, headers, exc_info)
            return self.application(environ, custom_start_response)
        elif server_token:
            # If we got a token, but no user, return a 401 with the token
            return self._unauthorized(start_response, server_token)
        else:
            # Otherwise, return a 403.
            return self._forbidden(start_response)
