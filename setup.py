# setup.py
from setuptools import setup, find_packages

setup(
    name='infrastructure_scanner',
    version='1.0',
    packages=find_packages(),
    install_requires=[
        'boto3',
        'pyyaml'
    ],
    entry_points={
        'console_scripts': [
            'scanner = src.scanner:main'
        ]
    }
)