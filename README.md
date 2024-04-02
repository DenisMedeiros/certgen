# certgen

An SSL certificate generator (and manager) for local development. This tool is able to generate a local CA certificate and from it, regular SSL certificates.
It also installs the CA certificate to the operating system so that most browsers can recognize the SSL certificates in your local development.

## Installation

Requirements:

- Python 3.10 or newer


### Using PIP

The example below shows the installation to the user-level. Feel free to install it in a virtual environment.

1. Install the certgen tool.

    ```bash
    pip install git+https://github.com/DenisMedeiros/certgen
    ```

### Using the Source Code

1. Clone or download this git repository.

    ```bash
    # SSH
    git clone git@github.com:DenisMedeiros/certgen.git

    # HTTPS
    git clone https://github.com/DenisMedeiros/certgen.git
    ```

2. Create a virtual environment, activate it, and install all dependencies.

    ```bash
    # Create venv.
    python3 -m venv venv

    # Activate it
    source venv/bin/activate.

    # Install dependencies.
    pip3 install requirements.txt
    ```

## Usage

See all options using the help menu:

```bash
# Top level menu.
python3 src/certgen.py -h/--help

# Certificate add menu.
python3 src/certgen.py add -h/--help
```

Example of the creation of a CA and SSL certificate.

```bash
python3 src/certgen.py add --domains example.com 192.168.0.10 hostname --output-dir /tmp/
```

Example of the creation of a CA and SSL certificate - this time, installing the CA file on the system.

```bash
python3 src/certgen.py add --install-ca --domains example.com 192.168.0.10 hostname --output-dir /tmp/
```

You can check of the certgen CA file is already installed on the system:

```bash
python3 src/certgen.py check
```

Finally, you can see the content of the generated files using the `openssl` CLI if you have it in your system:


```bash
# Inspect the CA file.
openssl x509 -inform pem -noout -text -in certgen.crt

# Inspect the certificate file.
openssl x509 -inform pem -noout -text -in certgen-ca.crt
```

**Important note**: every time a new CA file is (re)installed in the system, you may need to close and open your browser again so that it can load the system CA files.
