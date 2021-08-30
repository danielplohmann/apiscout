# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='apiscout',
    version='1.1.4',
    description='A library for Windows API usage recovery and similarity assessment with focus on memory dumps.',
    long_description_content_type="text/markdown",
    long_description=long_description,
    author='Daniel Plohmann',
    author_email='daniel.plohmann@mailbox.org',
    url='https://github.com/danielplohmann/apiscout',
    license="BSD 2-Clause",
    packages=find_packages(exclude=('tests', 'dbs')),
    package_data={'apiscout': ['data/winapi1024v1.txt', 'data/winapi_contexts.csv', 'data/html_frame.html']},
    data_files=[
        ('', ['LICENSE']),
    ],
    install_requires=[
        'numpy',
        'lief',
        'Pillow'
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Disassemblers",
    ],
)
