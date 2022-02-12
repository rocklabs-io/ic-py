#!/usr/bin/env python
import setuptools
from setuptools import setup
from os import path
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), 'r') as f:
    long_description = f.read()

setup(
    name = 'ic-py',
    version = '0.0.9',
    description = 'Python Agent Library for the Internet Computer',
    long_description = long_description,
    long_description_content_type = "text/markdown",
    url = 'https://github.com/rocklabs-io/ic-py',
    author = 'Rocklabs',
    author_email = 'hello@rocklabs.io',
    keywords = 'dfinity ic agent',
    install_requires = [
        'requests>=2.22.0', 
        'ecdsa>=0.18.0b2', 
        'cbor2>=5.4.2', 
        'leb128>=1.0.4', 
        'waiter>=1.2',
        'antlr4-python3-runtime==4.9.3'
        ],
    py_modules = ['ic'],
    package_dir = { 'ic': "ic" },
    packages = setuptools.find_packages(where='./'),
    include_package_data = True
)
