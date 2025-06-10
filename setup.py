#!/usr/bin/env python3

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="rigmaiden",
    version="1.0.0",
    author="Michael Mendy",
    author_email="your.email@example.com",
    description="A secure system management tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/rigmaiden",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: MacOS X",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.8",
    install_requires=[
        "psutil>=5.8.0",
        "cryptography>=3.4.0",
        "requests>=2.26.0",
        "python-dotenv>=0.19.0",
    ],
    entry_points={
        "console_scripts": [
            "rigmaiden=rigmaiden.rigmaiden:main",
        ],
    },
    data_files=[
        ("/etc", ["install/rigmaiden.ini"]),
        ("/usr/local/bin", ["install/rigmaiden"]),
    ],
    include_package_data=True,
    zip_safe=False,
)
