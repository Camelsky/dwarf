from setuptools import setup, find_packages
import os

setup(
    name = 'dwarf',
	version = '0.1.2',
    url = 'https://github.com/Camelsky/dwarf.git',
    license = 'MIT',
    author = 'camelsky',
    author_email = 'camelsky@gmail.com',
    description = 'tools for stat active user',
    zip_safe = False,
    platforms = 'any',
    packages=find_packages(exclude=['*.pyc']),
    # package_dir = {'': '.'},
    include_package_data = True,
    install_requires=[
        "bitarray",
    ],
)
