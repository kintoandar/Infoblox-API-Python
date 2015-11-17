import os

from setuptools import setup, find_packages

README = open('README.txt').read()

setup(
    name='pyinfobloxapi',
    version='1.1.0',
    description='The module implements Infoblox IPAM API via REST API',
    long_description=README,
    license = 'Licensed under the Apache License, Version 2.0',
    packages=['pyinfobloxapi'],
    install_requires=['requests'],
    include_package_data = True,
)
