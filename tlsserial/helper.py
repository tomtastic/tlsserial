""" Helper functions to parse pypy cryptography x509 objects """
import logging
import os
import socket
import ssl
from time import perf_counter
from typing import Dict  # Lets do static type checking with mypy
from click import Option, UsageError
from cryptography import x509
from cryptography.x509 import DNSName, ExtensionNotFound
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    # dh,
    # dsa,
    ec,
    # ed448,
    # ed25519,
    padding,
    rsa,
    # types,
    # x448,
    # x25519,
)
import pendulum

debug = False

NAME_ATTRIBS = (
    ("CN", NameOID.COMMON_NAME),
    ("O", NameOID.ORGANIZATION_NAME),
    ("L", NameOID.LOCALITY_NAME),
    ("ST", NameOID.STATE_OR_PROVINCE_NAME),
    ("C", NameOID.COUNTRY_NAME),
)

today = pendulum.now()
next_14d = today + pendulum.duration(days=14)
next_30d = today + pendulum.duration(days=30)
next_90d = today + pendulum.duration(days=90)


def timethis(func):
    """Sample decorator to report a function runtime in milliseconds"""
    """*** Warning ***"""
    """FIXME: Decorating some functions causes them to return NoneType"""

    def wrapper(*args, **kwargs):
        # Make sure we accept any number of args / keyword args
        time_before = perf_counter()
        func(*args, **kwargs)
        time_after = perf_counter()
        time_diff = time_after - time_before
        if debug:
            # __qualname__ returns the name of the func passed in
            logging.info(f"({func.__qualname__}) took {time_diff:.3f} seconds")

    return wrapper

class MutuallyExclusiveOption(Option):
    def __init__(self, *args, **kwargs):
        self.mutually_exclusive = set(kwargs.pop('mutually_exclusive', []))
        help = kwargs.get('help', '')
        if self.mutually_exclusive:
            ex_str = ', '.join(self.mutually_exclusive)
            kwargs['help'] = help + (
                ' NOTE: This argument is mutually exclusive with arguments: [' + ex_str + '].'
            )
        super(MutuallyExclusiveOption, self).__init__(*args, **kwargs)

    def handle_parse_result(self, ctx, opts, args):
        if self.mutually_exclusive.intersection(opts) and self.name in opts:
            raise UsageError(
                "Illegal usage: `{}` is mutually exclusive with arguments `{}`.".format(
                    self.name,
                    ', '.join(self.mutually_exclusive)
                )
            )

        return super(MutuallyExclusiveOption, self).handle_parse_result(
            ctx,
            opts,
            args
        )

def get_cert_from_host(host, port=443, timeout=8) -> tuple[None | x509.Certificate, str]:
    """Use ssl library to get certificate details from a host"""
    """Then use 'cryptography' to parse the certificate and return the ugly X509 object"""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout) as connection:
            with context.wrap_socket(connection, server_hostname=host) as sock:
                sock.settimeout(timeout)
                try:
                    der_cert = sock.getpeercert(True)
                finally:
                    sock.close()
                if der_cert is None:
                    return (None, "Failed to get peer certificate!")
                else:
                    cert_pem = ssl.DER_cert_to_PEM_cert(der_cert)
                    return (
                        # load_certificate takes a bytes object, so encode cert_pem
                        x509.load_pem_x509_certificate(str.encode(cert_pem)),
                        "SSL certificate"
                    )
    except socket.timeout:
        return (None, "Socket timeout!")
    except ssl.SSLEOFError:
        return (None, "SSL EOF error!")
    except ssl.SSLError as err:
        return (None, f"{err}")
    except socket.gaierror:
        return (None, "Socket getaddrinfo() error - Name or service not known!")
    except ConnectionError:
        return (None, "Connection error!")


def get_cert_from_file(filename: str, mode="r") -> tuple[None | x509.Certificate, str]:
    """Use ssl library to get certificate details from disk"""
    """Then use 'cryptography' to parse the certificate and return the ugly X509 object"""
    try:
        base = os.path.dirname(__file__)
        with open(os.path.join(base, filename), mode) as file:
            return (
                # load_certificate takes a bytes object, so encode cert_pem
                x509.load_pem_x509_certificate(str.encode(file.read())),
                "SSL certificate"
            )
    except ValueError as err:
        return (None, f"{err}")
    except FileNotFoundError as err:
        return (None, f"{err}")
    except PermissionError as err:
        return (None, f"{err}")


def get_issuer(cert: x509.Certificate):
    """Issuer"""
    issuer = []
    for a, b in NAME_ATTRIBS:
        for n in cert.issuer.get_attributes_for_oid(b):
            issuer.append(f"[{a}] {n.value}")
    return issuer


def get_subject(cert: x509.Certificate):
    """Subject"""
    subject = []
    for a, b in NAME_ATTRIBS:
        for n in cert.subject.get_attributes_for_oid(b):
            subject.append(f"[{a}] {n.value}")
    return subject


def get_sans(cert: x509.Certificate):
    """The Subject Alternative Names"""
    sans = cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    ).value.get_values_for_type(DNSName)
    return sans


def get_key_usage(cert: x509.Certificate):
    """Key usage"""
    key_usage = []
    key_usage_object = cert.extensions.get_extension_for_oid(
        ExtensionOID.KEY_USAGE
    ).value
    # <KeyUsage(
    #   digital_signature=True, content_commitment=False, key_encipherment=True,
    #   data_encipherment=False, key_agreement=False, key_cert_sign=False,
    #   crl_sign=False, encipher_only=False, decipher_only=False )>
    try:
        # Use the __dict__ method to return only instance attributes
        for attr, value in key_usage_object.__dict__.items():
            # Only return the enabled (True) Key Usage attributes
            if value is True:
                # No idea why the names are '_private'?
                key_usage.append(attr.lstrip("_"))
    except ValueError:
        pass
    return key_usage


def get_ext_key_usage(cert: x509.Certificate) -> list:
    """Returns list of Extended key usages"""
    ext_key_usage = []
    ext_key_usage_object = cert.extensions.get_extension_for_oid(
        ExtensionOID.EXTENDED_KEY_USAGE
    ).value
    # {'_usages': [
    #   <ObjectIdentifier(oid=1.3.6.1.5.5.7.3.1, name=serverAuth)>,
    #   <ObjectIdentifier(oid=1.3.6.1.5.5.7.3.2, name=clientAuth)> ]}
    try:
        for usage in ext_key_usage_object.__dict__["_usages"]:
            ext_key_usage.append(usage._name)
    except ValueError:
        pass
    return ext_key_usage


def get_before_and_after(cert: x509.Certificate) -> tuple:
    """Returns tuple of notAfter and notBefore datetimes"""
    # Ignore pyright parse export error, it's pendulums fault
    # https://github.com/sdispater/pendulum/pull/693
    notAfter = pendulum.parse(cert.not_valid_after.isoformat())
    notBefore = pendulum.parse(cert.not_valid_before.isoformat())
    return notBefore, notAfter


def get_crls(cert: x509.Certificate):
    """Returns CRLs"""
    # <CRLDistributionPoints([
    #   <DistributionPoint(
    #     full_name=[
    #       <UniformResourceIdentifier(value='http://crl.r2m01.amazontrust.com/r2m01.crl')>
    #     ],
    #     relative_name=None,
    #     reasons=None,
    #     crl_issuer=None
    #   )>
    # ])>
    crls = ""
    crl_distribution_points = []
    try:
        crl_distribution_points_object = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        ).value
        [
            crl_distribution_points.append(crl_dp.full_name)
            for _, crl_dp in enumerate(crl_distribution_points_object)
        ]
        for crl_list in crl_distribution_points:
            crls_list = []
            for crl in crl_list:
                crls_list.append(crl.value)
            crls = " ".join(crls_list)
    except (ValueError, ExtensionNotFound):
        pass
    return crls


def get_ocsp_and_caissuer(cert: x509.Certificate) -> tuple:
    """Returns tuple of OCSP and CA Issuers locations"""
    ocsp = ""
    ca_issuers = ""
    try:
        authorityInfoAccess = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )
        for access in authorityInfoAccess.value:
            name = access.access_method._name
            location = access.access_location._value
            if "OCSP" in name:
                ocsp = location
            elif "caIssuers" in name:
                ca_issuers = location
    except (ValueError, ExtensionNotFound):
        pass
    return ocsp, ca_issuers


def get_key_type(cert: x509.Certificate):
    """Return the public key type (eg. RSA/DSA/etc)"""
    public_key = cert.public_key()
    key_type = f"{type(public_key).__name__.lstrip('_')}"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        key_type += f" {public_key.public_numbers().curve.name}"
    return key_type


def get_key_bits(cert: x509.Certificate) -> int:
    """Returns the bit length of the public key"""
    key_bits = 0
    public_key = cert.public_key()
    # These are only of vague interest for CTF competitions, etc
    if isinstance(public_key, rsa.RSAPublicKey):
        key_bits = public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_bits = public_key.key_size
    return key_bits


def get_key_factors(cert: x509.Certificate) -> dict:
    """Returns dict w/ modulus size and exponent from public key bits"""
    """or other key factors where appropriate"""
    key_factors: Dict[str, int] = {}
    public_key = cert.public_key()
    # These are only of vague interest for CTF competitions, etc
    if isinstance(public_key, rsa.RSAPublicKey):
        key_factors["exponent"] = public_key.public_numbers().e
        key_factors["n"] = public_key.public_numbers().n
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_factors["x"] = public_key.public_numbers().x
        key_factors["y"] = public_key.public_numbers().y
    return key_factors

def get_sig_algorithm(cert: x509.Certificate):
    if isinstance(cert.signature_hash_algorithm, hashes.HashAlgorithm):
        sig_algo = cert.signature_hash_algorithm.name.upper()
    else:
        sig_algo = None
    return sig_algo


def get_sig_algorithm_params(cert: x509.Certificate) -> str:
    pss = cert.signature_algorithm_parameters
    try:
        if isinstance(pss, padding.PSS):
            return "PSS"
        elif isinstance(pss, padding.PKCS1v15):
            return "PKCS1v15"
        elif isinstance(pss, padding.ECDSA):
            return "ECDSA"
        else:
            return "n/a"
    except AttributeError:
        return "n/a"

