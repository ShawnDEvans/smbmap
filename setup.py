
import setuptools

with open("README.md", "r", encoding = "utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name = "smbmap",
    version = "1.8.2",
    author = "ShawnDEvans",
    author_email = "Shawn.Evans@knowledgeCG.com",
    description = " SMBMap is a handy SMB enumeration tool ",
    long_description = long_description,
    long_description_content_type = "text/markdown",
    url = "https://github.com/ShawnDEvans/smbmap",
    project_urls = {
        "Bug Tracker": "https://github.com/ShawnDEvans/smbmap/issues?q=is%3Aissue+is%3Aopen+sort%3Aupdated-desc",
    },
    classifiers = [
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    packages =[ "smbmap" ],
    python_requires = ">=3.6",
    install_requires = [
        'impacket',
        'pyasn1',
        'pycrypto',
        'configparser',
        'termcolor',
    ],
    entry_points={
        'console_scripts': [
            'smbmap=smbmap.smbmap:main'
        ]
    },
)
