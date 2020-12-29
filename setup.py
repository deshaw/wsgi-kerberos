"""
WSGI-Kerberos
-------------

Provides Kerberos authentication support for WSGI applications

Links
`````

* `documentation <https://wsgi-kerberos.readthedocs.org/en/latest/>`_
* `development version
  <http://github.com/deshaw/wsgi-kerberos/zipball/master#egg=wsgi-kerberos-dev>`_

"""

import os
import re
from setuptools import setup

lib = os.path.join(os.path.dirname(__file__), "wsgi_kerberos.py")
with open(lib) as fh:
    version = re.search(r"""__version__ = ["'](.*?)["']""", fh.read()).group(1)

setup(name='WSGI-Kerberos',
      version=version,
      url='https://github.com/deshaw/wsgi-kerberos',
      license='BSD-3-Clause',
      author='Michael Komitee',
      author_email='mkomitee@gmail.com',
      maintainer='Vitaly Shupak',
      maintainer_email='vitaly.shupak@deshaw.com',
      description='Kerberos authentication support in WSGI Middleware',
      long_description=__doc__,
      py_modules=['wsgi_kerberos'],
      zip_safe=False,
      include_package_data=True,
      package_data={'': ['LICENSE', 'AUTHORS']},
      platforms='any',
      install_requires=['kerberos < 2'],
      classifiers=['Development Status :: 4 - Beta',
                   'Environment :: Web Environment',
                   'Intended Audience :: Developers',
                   'License :: OSI Approved :: BSD License',
                   'Operating System :: OS Independent',
                   'Programming Language :: Python',
                   'Programming Language :: Python :: 2.7',
                   'Programming Language :: Python :: 3',
                   'Topic :: Internet :: WWW/HTTP',
                   'Topic :: Internet :: WWW/HTTP :: WSGI',
                   'Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware',
                   'Topic :: Software Development :: Libraries :: Python Modules'],
      test_suite='test_wsgi_kerberos',
      tests_require=['mock', 'WebTest'])
