import re
import os
import sys
import argparse
import logging
import datetime
import platform
import subprocess

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate

# Filenames and other default options for certs.
CA_NAME = "certgen-ca.crt"
CA_KEY_NAME = "certgen-ca.key"
CA_EXPIRATION_DAYS = 7300  # Equivalent to 20 years.
CERT_NAME = "certgen.crt"
KEY_NAME = "certgen.key"

# Regex rules.
HOSTNAME_RE = r"([a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*)"
IP_RE = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"


def validate_domain(value: str) -> str:
    """
    Validates whether the given value is a valid domain.

    Args:
        value (str): The value to be validated.

    Returns:
        str: The validated domain if it is valid.

    Raises:
        argparse.ArgumentTypeError: If the value is not a valid domain.
    """
    if re.match(HOSTNAME_RE, value) is not None or re.match(IP_RE, value):
        return value
    raise argparse.ArgumentTypeError(f"The value '{value}' is not a valid domain.")


def validate_dir(value: str) -> str:
    """
    Validates whether the given value is a valid directory and has write access.

    Args:
        value (str): The value representing the directory path.

    Returns:
        str: The validated directory path.

    Raises:
        argparse.ArgumentTypeError: If the value is not a valid directory or does not have write access.
    """
    path = Path(value)
    if not path.is_dir():
        raise argparse.ArgumentTypeError(f"The value '{value}' is not a valid directory.")
    if not os.access(path, os.W_OK):
        raise argparse.ArgumentTypeError(f"No write access to the directory '{value}'.")
    return path


def confirm_operation(question: str):
    """
    Asks the user to confirm an operation.

    Args:
        question (str): The question to ask the user.

    Returns:
        bool: True if the user confirms (by entering 'y' or 'Y'), False otherwise.
    """
    while True:
        user_input = input(f"{question} [y/N]: ").strip().upper() or "N"
        if user_input in ("Y", "N"):
            return user_input == "Y"
        else:
            print("Invalid input. Please enter 'y' or 'n'.")


def generate_ca(expiration: int) -> tuple[RSAPrivateKey, Certificate]:

    # Generate CA key.
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Generate CA certificate.
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "CertGen CA"),
    ])

    now_utc = datetime.datetime.now(tz=datetime.UTC)
    ca_cert_buider = x509.CertificateBuilder(
        subject_name=ca_name,
        issuer_name=ca_name,
        public_key=ca_key.public_key(),
        serial_number=x509.random_serial_number(),
        not_valid_before=now_utc,
        not_valid_after=now_utc + datetime.timedelta(days=expiration),
    )
    ca_cert_buider = ca_cert_buider.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    ca_cert = ca_cert_buider.sign(ca_key, algorithm=hashes.SHA256(), backend=default_backend())

    return (ca_key, ca_cert)


def save_key(key: RSAPrivateKey, file_path: Path):
    with open(file_path, 'wb') as file:
        file.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))


def save_cert(cert: Certificate, file_path: Path):
    with open(file_path, 'wb') as file:
        file.write(cert.public_bytes(serialization.Encoding.PEM))


def generate_cert(
        ca_cert: Certificate, ca_key:
        RSAPrivateKey,
        domains: list[str],
        expiration: int) -> tuple[RSAPrivateKey, Certificate]:

    # Generate certificate signing request (CSR) key.
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Generate CSR.
    common_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    csr_builder = x509.CertificateSigningRequestBuilder(
        subject_name=common_name,
    )

    # All add domains as subject alt names.
    subject_alt_names = []
    for domain in domains:
        if re.match(HOSTNAME_RE, domain):
            subject_alt_names.append(x509.DNSName(domain))
        elif re.match(IP_RE, domain):
            subject_alt_names.append(x509.IPAddress(domain))
        else:
            raise ValueError(f"The domain '{domain}' is not a valid value for subject alt name.")

    csr_builder = csr_builder.add_extension(x509.SubjectAlternativeName(subject_alt_names), critical=False)
    csr = csr_builder.sign(key, algorithm=hashes.SHA256(), backend=default_backend())

    # Generate the certificate (using certgen CA).
    now_utc = datetime.datetime.now(tz=datetime.UTC)
    cert_builder = x509.CertificateBuilder(
        subject_name=csr.subject,
        issuer_name=ca_cert.issuer,
        public_key=csr.public_key(),
        serial_number=x509.random_serial_number(),
        not_valid_before=now_utc,
        not_valid_after=now_utc + datetime.timedelta(days=expiration),
        extensions=csr.extensions,
    )

    # Sign the CSR with the CA
    cert = cert_builder.sign(ca_key, algorithm=hashes.SHA256(), backend=default_backend())
    return (key, cert)


def install_certgen_ca(local_ca_cert_path: Path, ca_cert_name: str):
    """
    Installs the certgen CA file in the system.

    Args:
        local_ca_cert_path (Path): The path to the certgen CA file.
        ca_cert_name (str): The name of the certgen CA file.

    Raises:
        Exception: If the installation process fails.
    """
    system_ca_cert_path = None
    platform_info = platform.freedesktop_os_release()
    match platform_info:
        case {"ID": "fedora"}:
            system_ca_cert_path = Path(os.path.join("/etc/pki/ca-trust/source/anchors/", ca_cert_name))

    try:
        subprocess.run(["sudo", "cp", local_ca_cert_path, system_ca_cert_path], check=True)
    except subprocess.CalledProcessError as err:
        logging.error(f"Failed to copy certgen CA file to system folder. {err}")
        raise err

    try:
        subprocess.run(["sudo", "update-ca-trust"], check=True)
    except subprocess.CalledProcessError as err:
        logging.error(f"Failed to update CA trust. {err}")
        raise err


def create_certificate(domains: list[str], expiration: int, output_dir: Path, install_ca: bool):
    ca_key_path = Path(os.path.join(output_dir, CA_KEY_NAME))
    ca_cert_path = Path(os.path.join(output_dir, CA_NAME))
    key_path = Path(os.path.join(output_dir, KEY_NAME))
    cert_path = Path(os.path.join(output_dir, CERT_NAME))
    if any([entry.exists() for entry in [ca_key_path, ca_cert_path, key_path, cert_path]]):
        logging.warning(f"There are certificarte files in the directory '{output_dir}'.")
        if not confirm_operation("Do you want to overwrite all CA and cert files?"):
            logging.info("Aborting certificate creation.")
            return

    summary = "".join([
        f"\n\tDomains: {', '.join(domains)}",
        f"\n\tCA Expiration: {CA_EXPIRATION_DAYS} days ({CA_EXPIRATION_DAYS//365} years)",
        f"\n\tCertificate Expiration: {expiration} days",
        f"\n\tOutput Dir: {output_dir}",
        f"\n\tInstall CA: {install_ca}",
    ])
    logging.info(f"Generating new CA and certificate with the following options: {summary}")
    ca_key, ca_cert = generate_ca(CA_EXPIRATION_DAYS)
    key, cert = generate_cert(ca_cert, ca_key, domains, expiration)

    logging.info(f"Saving CA certificate file '{CA_NAME}'...")
    save_cert(ca_cert, ca_cert_path)
    logging.info(f"Saving CA key file '{CA_KEY_NAME}'...")
    save_key(ca_key, ca_key_path)
    logging.info(f"Saving certificate file '{CERT_NAME}'...")
    save_cert(cert, cert_path)
    logging.info(f"Saving certificate key file '{CA_KEY_NAME}'...")
    save_key(key, key_path)

    if install_ca:
        system_ca_cert_path = get_certgen_ca_system_path(CA_NAME)
        if system_ca_cert_path.exists():
            if not confirm_operation("Do you want to overwrite the certgen CA installation on your OS?"):
                logging.info("Aborting certgen CA installation.")
                return
        logging.info("Installing the certgen CA file in this system...")
        install_certgen_ca(ca_cert_path, CA_NAME)


def get_certgen_ca_system_path(ca_cert_name: str) -> Path:
    """
    Gets the system path for the certgen CA file.

    Args:
        ca_cert_name (str): The name of the certgen CA file.

    Returns:
        Path: The system path for the certgen CA file.

    Raises:
        NotImplementedError: If the operating system is not supported.
    """
    platform_info = platform.freedesktop_os_release()
    match platform_info:
        case {"ID": "fedora"}:
            return Path(os.path.join("/etc/pki/ca-trust/source/anchors/", ca_cert_name))
        case _:
            raise NotImplementedError("Unsupported operating system.")


def check_certgen_ca():
    """
    Checks if the certgen CA file is installed in the system.
    """
    system_ca_cert_path = get_certgen_ca_system_path(CA_NAME)
    if not system_ca_cert_path.exists():
        logging.info("The certgen CA is not installed in this system.")
        return

    # At this point, the certgen is installed.
    with open(system_ca_cert_path, "rb") as ca_file:
        ca_cert_data = ca_file.read()
    ca_cert = x509.load_pem_x509_certificate(ca_cert_data, default_backend())
    summary = ''.join([
        f"\n\tIssuer: {ca_cert.issuer.rfc4514_string()}",
        f"\n\tSerial Number: {ca_cert.serial_number}",
        f"\n\tCreation: {ca_cert.not_valid_before_utc}",
        f"\n\tExpiration: {ca_cert.not_valid_after_utc}",
    ])
    logging.info(f"The certgen CA file is already installed. More details: {summary}")


def remove_certgen_ca():
    """
    Removes the certgen CA from the system (if installed).
    """
    system_ca_cert_path = get_certgen_ca_system_path(CA_NAME)
    if not system_ca_cert_path.exists():
        logging.warning("The certgen CA file is already removed from this system.")
        return

    if not confirm_operation("Do you really want to remove the certgen CA file from the system?"):
        logging.info("Aborting certgen CA removal.")
        return

    try:
        subprocess.run(["sudo", "rm", system_ca_cert_path], check=True)
    except subprocess.CalledProcessError as err:
        logging.error(f"Failed to remove certgen CA file to system folder. {err}")
        raise err

    try:
        subprocess.run(["sudo", "update-ca-trust"], check=True)
    except subprocess.CalledProcessError as err:
        logging.error(f"Failed to update CA trust. {err}")
        raise err


def main():
    """
    Main function to parse arguments and execute the program.
    """
    parser = argparse.ArgumentParser(description='SSL Self-Signed Certificate Generator')
    subparsers = parser.add_subparsers(title="Operation", dest="operation", help="Available operations", required=True)

    # Subparser for 'add' command.
    parser_add = subparsers.add_parser("add", help="Create a new certgen CA and SSL certificates.")
    parser_add.add_argument("-d", "--domains", nargs='+', type=validate_domain, required=True,
                            help="The list of domains to be included in the certificate.")
    parser_add.add_argument("-o", "--output-dir", type=validate_dir, required=False,
                            default=Path(os.getcwd()), help="The list of domains to be included in the certificate.")
    parser_add.add_argument("-e", "--expiration", type=int, required=False,
                            default=365, help="The expiration for the certificate (number of days).")
    parser_add.add_argument("--install-ca", action="store_true",
                            default=False, help="If the CA file must be installed in the local (OS) CA store.")

    # Subparser for 'check' command.
    subparsers.add_parser("check", help="Check if the certgen CA file is installed in the system.")

    # Subparser for 'remove' command.
    subparsers.add_parser("remove", help="Remove the certgen CA from the system (if installed).")
    args = vars(parser.parse_args())

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s :: %(levelname)s :: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.info("Starting certgen...")

    print(args)

    match args:
        case {"operation": "add"}:
            create_certificate(args["domains"], args["expiration"], args["output_dir"], args["install_ca"])
        case {"operation": "check"}:
            check_certgen_ca()
        case {"operation": "remove"}:
            remove_certgen_ca()

    logging.info("Certgen finished.")


if __name__ == "__main__":
    main()
