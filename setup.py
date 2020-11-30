from setuptools import setup, find_packages

setup(
    name='smrop',
    version='0.1',
    author="Chris Greene",
    author_email="archgoon+smrop@gmail.com",
    license="MIT",
    packages=['smrop'],
    install_requires=["pwn", "ROPgadget"]
)