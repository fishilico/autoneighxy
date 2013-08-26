#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
import os
import re

root_dir = os.path.abspath(os.path.dirname(__file__))


def get_version(package_name):
    version_re = re.compile(r"^__version__ = [\"']([\w_.-]+)[\"']$")
    package_components = package_name.split('.')
    path_components = package_components + ['__init__.py']
    with open(os.path.join(root_dir, *path_components)) as f:
        for line in f:
            match = version_re.match(line[:-1])
            if match:
                return match.groups()[0]
    return '0.1.0'


PACKAGE = 'autoneighxy'


setup(
    name=PACKAGE,
    version=get_version(PACKAGE),
    author='Nicolas Iooss',
    author_email='nicolas.iooss+autoneighxy@m4x.org',
    description="Automatic Neighbor Proxy",
    license='MIT',
    keywords=['ip', 'ndpproxy', 'daemon'],
    url='http://github.com/fishilico/autoneighxy',
    download_url='http://github.com/fishilico/autoneighxy',
    packages=find_packages(),
    install_requires=[
        'distribute',
    ],
    scripts=[
        'bin/autoneighxy',
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: No Input/Output (Daemon)',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Topic :: Internet :: Routing',
        'Operating System :: Unix',
        'Programming Language :: Python :: 2',
    ],
)
