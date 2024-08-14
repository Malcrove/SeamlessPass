from setuptools import setup, find_packages

with open("README.md") as f:
    readme = f.read()

setup(
    name="seamlesspass",
    description="Leveraging Kerberos tickets to get cloud access tokens using Seamless SSO",
    version="0.0.1",
    license="MIT",
    author="0xSyndr0me",
    url="https://github.com/malcrove/SeamlessPass",
    long_description=readme,
    long_description_content_type="text/markdown",
    install_requires=[
        "pyasn1",
        "impacket",
        "requests",
        "colorama"
    ],
    packages=find_packages(),
    entry_points={
        "console_scripts": ["seamlesspass=seamlesspass.main:main"],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    
)
