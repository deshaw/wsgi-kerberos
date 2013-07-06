#!/usr/bin/env python

def example(environ, start_response):
    user = environ.get('REMOTE_USER', 'ANONYMOUS')
    start_response('200 OK', [('Content-Type', 'text/plain')])
    return ["Hello, %s" % user]

if __name__ == '__main__':
    from wsgiref.simple_server import make_server
    from wsgi_kerberos import KerberosAuthMiddleware
    from socket import gethostname
    import logging
    logging.basicConfig()
    application = KerberosAuthMiddleware(example)
    server = make_server(gethostname(), 8080, application)
    server.serve_forever()
