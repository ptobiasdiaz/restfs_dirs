#!/usr/bin/env python3

'''Ejemplo de API REST para ADI'''

from setuptools import setup

setup(
    name='restfs-dirs',
    version='0.1',
    description=__doc__,
    packages=['restfs_dirs'],
    entry_points={
        'console_scripts': [
            'directory_service=restfs_dirs.server:main'
        ]
    }
)