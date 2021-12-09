#!/usr/bin/env python
from setuptools import setup
from os import path
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'readme.md'), 'r') as f:
    long_description = f.read()

setup(
    name = 'ic-py',
    version = '0.0.1',
    description = 'Python Agent Library for the IC',
    long_description = long_description,
    long_description_content_type = "text/markdown",
    url = 'https://github.com/rocklabs-io/ic-py',
    author = 'Rocklabs',
    author_email = 'ccyanxyz@gmail.com',
    keywords = 'dfinity ic agent',
    install_requires = ['requests>=2.22.0', 'cryptography>=36.0.0', 'cbor2>=5.4.2'],
    py_modules = ['ic'],
    include_package_data = True
)
