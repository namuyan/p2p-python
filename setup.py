#!/user/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
import os

try:
    with open('README.md') as f:
        readme = f.read()
except (IOError, UnicodeError):
    readme = ''


def _requires_from_file(filename):
    return open(filename).read().splitlines()


# version
here = os.path.dirname(os.path.abspath(__file__))
ver_path = os.path.join(here,'p2p_python', '__init__.py')
version = next((line.split('=')[1].strip().replace("'", '')
                for line in open(ver_path)
                if line.startswith('__version__ = ')),
               '0.0.dev0')

setup(
    name="p2p_python",
    version=version,
    url='https://github.com/namuyan/p2p-python',
    author='namuyan',
    description='Simple peer2peer library.',
    long_description=readme,
    packages=find_packages(),
    include_package_data=True,
    license="MIT Licence",
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'License :: OSI Approved :: MIT License',
    ],
)