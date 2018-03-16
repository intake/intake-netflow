#!/usr/bin/env python

from setuptools import setup, find_packages


requires = open('requirements.txt').read().strip().split('\n')

setup(
    name='intake-netflow',
    version='0.0.1',
    description='Intake Netflow plugin',
    url='https://github.com/ContinuumIO/intake-netflow',
    maintainer='Joseph Crail',
    maintainer_email='jbcrail@gmail.com',
    license='BSD',
    packages=find_packages(),
    package_data={'': ['*.yml', '*.html']},
    include_package_data=True,
    install_requires=requires,
    long_description=open('README.md').read(),
    zip_safe=False,
)
