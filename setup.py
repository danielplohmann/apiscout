# -*- coding: utf-8 -*-

from setuptools import setup, find_packages


with open('README.rst') as f:
    README = f.read()

with open('LICENSE') as f:
    LICENSE = f.read()

setup(
    name='apiscout',
    version='1.0.0',
    description='Windows API recovery.',
    long_description=README,
    author='Daniel Plohmann',
    author_email='daniel.plohmann@mailbox.org',
    url='https://github.com/daniel-plohmann/apiscout',
    license=LICENSE,
    # packages=find_packages(exclude=('tests', 'docs')),
    packages = ["apiscout"],
    package_data={"apiscout": ["data/winapi1024v1.txt"]},
)
