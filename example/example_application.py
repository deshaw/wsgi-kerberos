#!/usr/bin/env python3

import logging
from wsgi_kerberos import KerberosAuthMiddleware
from wsgiref.simple_server import make_server


def example(environ, start_response):
    user = environ.get('REMOTE_USER', 'ANONYMOUS')
    start_response('200 OK', [('Content-Type', 'text/plain')])
    data = "Hello {}".format(user)
    return [data.encode()]


application = KerberosAuthMiddleware(example)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    server = make_server('', 8080, application)
    server.serve_forever()
