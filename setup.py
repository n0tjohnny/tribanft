from setuptools import setup, find_packages

setup(
    name="tribanft",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "pydantic",
    ],
    entry_points={
        'console_scripts': [
            'tribanft=bruteforce_detector.main:main',
        ],
    },
)
