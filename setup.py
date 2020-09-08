#!/user/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
import os

__locals = dict()
root_dir = os.path.dirname(os.path.abspath(__file__))

# version
exec(open(os.path.join(root_dir, "p2p_python", "__init__.py")).read(), __locals)
version = __locals.get("__version__", "unknown")

# readme
with open(os.path.join(root_dir, "README.md")) as fp:
    readme = fp.read()

# requirements.txt
# https://github.com/pypa/setuptools/issues/1080
with open(os.path.join(root_dir, "requirements.txt")) as fp:
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
    python_requires=">=3.6",
    license="MIT Licence",
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        "Topic :: System :: Networking",
        "Typing :: Typed",
    ],
)
