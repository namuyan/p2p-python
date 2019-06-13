#!/user/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
import os

try:
    with open('README.md') as f:
        readme = f.read()
except (IOError, UnicodeError):
    readme = ''

# version
here = os.path.dirname(os.path.abspath(__file__))
ver_path = os.path.join(here, 'p2p_python', '__init__.py')
version = next((line.split('=')[1].strip().replace("'", '')
                for line in open(ver_path)
                if line.startswith('__version__ = ')),
               '0.0.dev0')

# requirements.txt
# https://github.com/pypa/setuptools/issues/1080
with open(os.path.join(here, 'requirements.txt')) as fp:
    install_requires = fp.read()


setup(
    name="p2p_python",
    version=version,
    url='https://github.com/namuyan/p2p-python',
    author='namuyan',
    description='Simple peer2peer library.',
    long_description=readme,
    long_description_content_type='text/markdown',
    packages=find_packages(),
    install_requires=install_requires,
    include_package_data=True,
    python_requires=">=3.6",
    license="MIT Licence",
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'License :: OSI Approved :: MIT License',
    ],
)
