
from setuptools import setup, find_packages
import os
import sys

requires = [
    'msgpack-python',
    'pycrypto',
    'setuptools',
]

if sys.version_info[:2] < (2, 7):
    requires.append('unittest2')

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.txt')).read()
CHANGES = open(os.path.join(here, 'CHANGES.txt')).read()

setup(
    name='randenc',
    version='0.1',
    description='Randomized Encryption Library',
    long_description=README + '\n\n' +  CHANGES,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python",
    ],
    license="BSD-derived (http://www.repoze.org/LICENSE.txt)",
    author='Shane Hathaway',
    author_email='shane@hathawaymix.org',
    url='https://github.com/hathawsh/randenc',
    keywords='encrypt ',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    include_package_data=True,
    zip_safe=False,
    test_suite='randenc',
    install_requires=requires,
    entry_points="""
    """,
)
