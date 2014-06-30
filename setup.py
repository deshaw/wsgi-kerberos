"""
WSGI-Kerberos
-------------

Provides Kerberos authentication support for WSGI applications

Links
`````

* `documentation <https://wsgi-kerberos.readthedocs.org/en/latest/>`_
* `development version
  <http://github.com/mkomitee/wsgi-kerberos/zipball/master#egg=wsgi-kerberos-dev>`_

"""

from setuptools import setup

setup(name='WSGI-Kerberos',
      version='0.2.0',
      url='http://github.com/mkomitee/wsgi-kerberos',
      license='BSD',
      author='Michael Komitee',
      author_email='mkomitee@gmail.com',
      description='Kerberos authentication support in WSGI Middleware',
      long_description=__doc__,
      py_modules=['wsgi_kerberos'],
      zip_safe=False,
      include_package_data=True,
      package_data={'': ['LICENSE', 'AUTHORS']},
      platforms='any',
      install_requires=['kerberos'],
      classifiers=['Development Status :: 4 - Beta',
                   'Environment :: Web Environment',
                   'Intended Audience :: Developers',
                   'License :: OSI Approved :: BSD License',
                   'Operating System :: OS Independent',
                   'Programming Language :: Python',
                   'Topic :: Internet :: WWW/HTTP',
                   'Topic :: Internet :: WWW/HTTP :: WSGI',
                   'Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware',
                   'Topic :: Software Development :: Libraries :: Python Modules'],
      test_suite='test_wsgi_kerberos',
      tests_require=['mock', 'WebTest'])
