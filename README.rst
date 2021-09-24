WSGI-Kerberos
==============

WSGI-Kerberos is `WSGI`_ Middleware which implements `Kerberos`_ authentication.
It makes it easy to add Kerberos authentication to any WSGI application.

Its only dependency is `python-kerberos`_ and it's been tested up to version 1.3.0

You can install the requirements from PyPI with ``easy_install`` or ``pip`` or
download them by hand.

Unfortunately, as is the case with most things kerberos, it requires a kerberos
environment as well as a keytab. Setting that up is outside the scope of this
document.

The official copy of this documentation is available at `Read the Docs`_.

Installation
------------

Install the extension with pip:

    $ pip install WSGI-Kerberos

How to Use
----------

To integrate ``WSGI-Kerberos`` into your application you'll need to generate
your keytab and set the environment variable ``KRB5_KTNAME`` in your shell to
the location of the keytab file.

After that, it should be as easy as passing your application to the
``KerberosAuthMiddleware`` constructor.  All requests destined for the
application will first be authenticated by the middleware, and the authenticated
users principal will be available as the ``REMOTE_USER`` in the WSGI
environment.

For example::

    from wsgiref.simple_server import make_server
    from wsgi_kerberos import KerberosAuthMiddleware

    def example(environ, start_response):
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return ['Hello, {}'.format(environ['REMOTE_USER']).encode()]

    if __name__ == '__main__':
        app = KerberosAuthMiddleware(example)
        http = make_server('', 8080, app)
        http.serve_forever()


``WSGI-Kerberos`` assumes that every request should be authenticated. If this is
not the case, you can override it by passing in a callback named
``auth_required_callback`` to the
``KerberosAuthMiddleware`` constructor. This callback will be called for every
request and passed the wsgi environment object::

    from wsgiref.simple_server import make_server
    from wsgi_kerberos import KerberosAuthMiddleware

    def example(environ, start_response):
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return ['Hello, {}'.format(environ.get('REMOTE_USER', 'ANONYMOUS').encode()]

    def authenticate(environ):
        return environ['PATH_INFO'].startswith('/protected'):

    if __name__ == '__main__':
        app = KerberosAuthMiddleware(example,
                                     auth_required_callback=authenticate)
        http = make_server('', 8080, app)
        http.serve_forever()


By default, when ``WSGI-Kerberos`` responds with a ``401`` to indicate that
authentication is required, it generates a very simple page with a
``Content-Type`` of ``text/plain`` that includes the string ``Unauthorized``.

Similarly, when it responds with a ``403`` indicating that authentication has
failed, it generates another simple page with a ``Content-Type`` of
``text/plain`` that includes the string ``Forbidden``.

These can be customized::

    from wsgiref.simple_server import make_server
    from wsgi_kerberos import KerberosAuthMiddleware

    def example(environ, start_response):
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return ['Hello, {}'.format(environ['REMOTE_USER']).encode()]

    if __name__ == '__main__':
        app = KerberosAuthMiddleware(example,
                                     unauthorized='Authentication Required',
                                     forbidden='Authentication Failed')
        http = make_server('', 8080, app)
        http.serve_forever()

You can also change the ``Content-Types`` by passing in string/content-type
tuples::

    from wsgi_kerberos import KerberosAuthMiddleware
    from wsgiref.simple_server import make_server

    def example(environ, start_response):
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return ['Hello, {}'.format(environ['REMOTE_USER']).encode()]

    if __name__ == '__main__':
        forbidden='''
        <html>
            <body>
                <h1>GO AWAY</h1>
            </body
        </html>
        '''

        unauthorized='''
        <html>
            <body>
                <h1>TRY AGAIN</h1>
            </body
        </html>
        '''

        app = KerberosAuthMiddleware(example,
                                     unauthorized=(unauthorized, 'text/html'),
                                     forbidden=(forbidden, 'text/plain'))
        http = make_server('', 8080, app)
        http.serve_forever()



``WSGI-Kerberos`` will authenticate the request using any hostname in the
keytab file. You can restrict requests to one specific hostname by passing it
to the ``KerberosAuthMiddleware`` constructor::

    from wsgiref.simple_server import make_server
    from wsgi_kerberos import KerberosAuthMiddleware

    def example(environ, start_response):
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return ['Hello, {}'.format(environ['REMOTE_USER']).encode()]

    if __name__ == '__main__':
        app = KerberosAuthMiddleware(example, hostname='example.com')
        http = make_server('', 8080, app)
        http.serve_forever()


How it works
------------

When an application which uses the middleware is accessed by a client, it will
check to see if the request includes authentication credentials in an
``Authorization`` header. If there are no such credentials, the application will
respond immediately with a ``401 Unauthorized`` response which includes a
``WWW-Authenticate`` header field with a value of ``Negotiate`` indicating to
the client that they are currently unauthorized, but that they can authenticate
using Negotiate authentication.

If credentials are presented in the ``Authorization`` header, the credentials
will be validated, the principal of the authenticating user will be extracted
and added to the WSGI environment using the key ``REMOTE_USER``, and the
application will be called to serve the request, but instead of being passed the
default WSGI ``start_response`` function, it will be passed a slightly modified
one which appends a ``WWW-Authenticate`` header which identifies the server to
the client.  This allows ``WSGI-Kerberos`` to support mutual authentication.


Full Example
------------

To see a simple example, you can download the code `from github
<http://github.com/deshaw/wsgi-kerberos>`_. It is in the example directory.

Changes
-------

1.0.2 (2021-09-24)
``````````````````

-   Set content-length header on 401/403 responses.

1.0.1 (2021-01-18)
``````````````````

-   Fix an issue introduced in v1.0.0 that could cause the server to hang
    after receiving a request with no body that could not be authenticated.
-   When a request could not be authenticated, WSGI-Kerberos now buffers no
    more than 64K of the request at a time before sending the response.
-   Increase the default `read_max_on_auth_fail` from 10 MB to 100 MB.

1.0.0 (2020-12-28)
``````````````````
-    `hostname` no longer needs to be specified in KerberosAuthMiddleware
     constructor - any hostname in the keytab will be accepted
-    Set REMOTE_USER when valid auth is provided, even if not required
-    Limit the number of bytes read in request bodies on auth failure to
     mitigate a possible DoS attack. New parameter `read_max_on_auth_fail`
     can be set to customize or remove the limit.
     **NOTE:** This can cause some clients, for example
     requests/requests_kerberos, to get connection errors, due to naively
     uploading arbitrarily large request bodies that they expect the server
     to read entirely, including when the request omitted credentials,
     before checking for an authentication failure response.
     Such clients may set `force_preemptive=True` (or equivalent) to try to
     avoid getting connection errors.
     To disable the DoS protection completely,
     pass WSGI-Kerberos `read_max_on_auth_fail=float("inf")`.
-    Support clients which don't request mutual authentication
-    Log Kerberos errors
-    Validate first word in Authorization header
-    Python 3 compatibility fixes
-    Various bug fixes
-    Update license from BSD-2-Clause to BSD-3-Clause
-    Project was moved to the D. E. Shaw Org

0.2.0
`````

-     bug fixes

0.1.0
`````

-     initial implementation


API References
--------------

The full API reference:


.. automodule:: wsgi_kerberos
   :members:

.. _WSGI: http://wsgi.readthedocs.org/en/latest/
.. _Kerberos: http://wikipedia.org/wiki/Kerberos_(protocol)
.. _python-kerberos: http://pypi.python.org/pypi/kerberos
.. _Read the Docs: https://wsgi-kerberos.readthedocs.org/

History
=======
This plugin was contributed back to the community by the `D. E. Shaw group
<https://www.deshaw.com/>`_.

.. raw:: html

   <p align="center">
       <a href="https://www.deshaw.com">
          <img src="https://www.deshaw.com/assets/logos/blue_logo_417x125.png" alt" height="75" >
       </a>
   </p>
