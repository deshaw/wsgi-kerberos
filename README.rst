WSGI-Kerberos
==============

WSGI-Kerberos is `WSGI`_ Middleware which implements `Kerberos`_ authentication.
It makes it easy to add Kerberos authentication to any WSGI application.

Its only dependency is `python-kerberos`_ and it's been tested against version
1.1.1.

You can install the requirements from PyPI with ``easy_install`` or ``pip`` or
download them by hand.

Unfortunately, as is the case with most things kerberos, it requires a kerberos
environment as well as a keytab. Setting that up is outside the scope of this
document.

The official copy of this documentation is available at `Read the Docs`_.

Installation
------------

Install the extension with one of the following commands::

    $ easy_install WSGI-Kerberos

or alternatively if you have ``pip`` installed::

    $ pip install WSGI-Kerberos

How to Use
----------

To integrate ``WSGI-Kerberos`` into your application you'll need to generate
your keytab set the environment variable ``KRB5_KTNAME`` in your shell to the
location of the keytab file.

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
        return ['Hello, %s' % environ['REMOTE_USER']]

    if __name__ == '__main__':
        app = KerberosAuthMiddleware(example)
        http = make_server('', 80, app)
        http.serve_forever()


``WSGI-Kerberos`` assumes that the service will be running using the hostname of
the host on which the application is run. If this is not the case, you can
override it by passing in a hostname to the ``KerberosAuthMiddleware``
constructor::

    from wsgiref.simple_server import make_server
    from wsgi_kerberos import KerberosAuthMiddleware

    def example(environ, start_response):
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return ['Hello, %s' % environ['REMOTE_USER']]

    if __name__ == '__main__':
        app = KerberosAuthMiddleware(example, hostname='example.com')
        http = make_server('', 80, app)
        http.serve_forever()

``WSGI-Kerberos`` assumes that every request should be authenticated. If this is
not the case, you can override it by passing in a callback named to the
``KerberosAuthMiddleware`` constructor. This callback will be called for every
request and passed the wsgi environment object::

    from wsgiref.simple_server import make_server
    from wsgi_kerberos import KerberosAuthMiddleware

    def example(environ, start_response):
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return ['Hello, %s' % environ.get('REMOTE_USER', 'ANONYMOUS')]

    def authenticate(environ):
        return environ['PATH_INFO'].startswith('/protected'):

    if __name__ == '__main__':
        app = KerberosAuthMiddleware(example,
                                     auth_required_callback=authenticate)
        http = make_server('', 80, app)
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
        return ['Hello, %s' % environ['REMOTE_USER']]

    if __name__ == '__main__':
        app = KerberosAuthMiddleware(example,
                                     unauthorized='Authentication Required',
                                     forbidden='Authentication Failed')
        http = make_server('', 80, app)
        http.serve_forever()

You can also change the ``Content-Types`` by passing in string/content-type
tuples::

    from wsgi_kerberos import KerberosAuthMiddleware
    from wsgiref.simple_server import make_server

    def example(environ, start_response):
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return ['Hello, %s' % environ['REMOTE_USER']]

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
        http = make_server('', 80, app)
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
<http://github.com/mkomitee/wsgi-kerberos>`_. It is in the example directory.

Changes
-------

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
