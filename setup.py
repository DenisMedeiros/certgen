from setuptools import setup

setup(
    name="certgen",
    version="0.1.0",
    description="An SSL certificate generator for development purposes.",
    url="https://github.com/DenisMedeiros/certgen",
    author="Denis Medeiros",
    author_email="dnsricardo@gmail.com",
    license="MIT",
    packages=["certgen"],
    package_dir={"": "src"},
    install_requires=[
        "cryptography==42.0.5",
    ],
    entry_points={
        "console_scripts": [
            "certgen = certgen.certgen:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.10",
    ],
)