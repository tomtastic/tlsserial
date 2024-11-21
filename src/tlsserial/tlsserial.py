#!/usr/bin/env python3
"""grab some things from a TLS cert"""

# TODO:
# - Report TLS1.3 negotiation for url lookups as NIST SP 800-52 requires support by Jan 2024
# - Swap back to the pyOpenSSL lib to allow getting entire chain from a host?
#   - No need, we can use a private method from ssl
# - Show the SHA-256 hash of the subject Public Key Information
# - Clearly show SANs with specifier, eg.
#     DNS:*.axiom-partners.com
# - Compare against INTB (and others) cipher suite?
#   NB: Committee on National Security Systems Instruction (CNSSI) 1253 Intelligence Overlay B (INT-B)
#   NB: INT-A for the least sensitive data through INT-C for the most sensitive data
#   NB: CNSA: The algorithm is recommended by NSA (Commercial National Security Algorithm (CNSA) Suite formerly NSA's Suite B program).
#   - Clarify ciphers in use
#     eg.
#       - peer signing digest
#       - server temp keys
#       - server public keys
#       - TLS cipher?
import re
import sys

import click
from cryptography import x509

from . import helper
from .color import blue, bold, orange, red
from .nice_certificate import NiceCertificate


def handle_url(url: str, verbose: bool = False) -> None:
    """host || host:port || https://host:port/other."""
    try:
        host, port = get_args(url)
    except ValueError as err:
        print(err)
        sys.exit(1)
    # Assigns all certificates found to tuple cert([c1, c2, ...], "SSL cert")
    cert_chain = helper.get_certs_from_host(host, port)
    if cert_chain[0] is not None:
        for cert in reversed(cert_chain[0]):
            display(host, parse_x509(cert), verbose)
    else:
        print(cert_chain[1])


def handle_file(file: str, verbose: bool = False) -> None:
    """
    filename containing a PEM certificate
    """
    host = ""
    # Assigns all certificates found to tuple cert([c1, c2, ...], "SSL cert")
    cert_chain = helper.get_certs_from_file(file)
    if cert_chain[0] is not None:
        for cert in reversed(cert_chain[0]):
            display(host, parse_x509(cert), verbose)
            click.echo("")
    else:
        print(cert_chain[1])


def get_args(argv: str) -> tuple:
    # TODO: https://docs.python.org/3/library/urllib.parse.html#url-parsing
    """
    Try to extract a hostname and port from input string
    Returns a tuple of (host, port)
    """
    args_matched = re.search(r"([0-9a-zA-Z\-\.]{6,63})[\ :]?([0-9]{2,5})?", argv)
    if args_matched is not None:
        if args_matched[1] is not None:
            if args_matched[1] is not None:
                if args_matched[2] is not None and args_matched[2].isdigit:
                    # host and specified port
                    return (args_matched[1], args_matched[2])
                # host and default port
                return (args_matched[1], 443)
    raise ValueError(f"Error parsing the input : {argv}")


def parse_x509(cert: x509.Certificate) -> NiceCertificate:
    """Parse an ugly X509 object.

    Return a NiceCertificate object.
    """
    # We use helper functions where parsing is gnarly
    not_before, not_after = helper.get_before_and_after(cert)
    ocsp, ca_issuers = helper.get_ocsp_and_caissuer(cert)

    return NiceCertificate(
        # We use helper functions where parsing is gnarly
        version=helper.get_version(cert),
        issuer=helper.get_issuer(cert),
        ca_issuers=ca_issuers,
        subject=helper.get_subject(cert),
        sans=helper.get_sans(cert),
        basic_constraints=helper.get_basic_constraints(cert),
        key_usage=helper.get_key_usage(cert),
        ext_key_usage=helper.get_ext_key_usage(cert),
        not_before=not_before,
        not_after=not_after,
        crls=helper.get_crls(cert),
        ocsp=ocsp,
        serial_as_int=cert.serial_number,
        key_type=helper.get_key_type(cert),
        key_bits=helper.get_key_bits(cert),
        key_factors=helper.get_key_factors(cert),
        sig_algo=helper.get_sig_algorithm(cert),
        sig_algo_params=helper.get_sig_algorithm_params(cert),
    )


def display(host: str, cert: NiceCertificate, debug: bool) -> None:
    """Print nicely-formatted attributes of a NiceCertificate object."""
    # TODO: This function is long and hard to follow. a lot of the `elif`s could be separate
    # functions and be individually testable.
    # Maybe use a match/case instead of the big if/elif/else (>=py310)
    print_items = [
        "version",
        "issuer",
        "subject",
        "subject_alt_name",
        "basic_constraints",
        "not_before",
        "not_after",
        "public_key_algorithm",
        "signature_algorithm",
        "key_usage",
        "ext_key_usage",
        "crls",
        "ocsp",
        "ca_issuers",
        "chain",
        "serial_number",
    ]

    width = 24
    matched_host = False
    # TODO:  Rather than having a lot of print statements here, split the responsibility of building the
    # string from the output. Build up a string in one function and return it, then in another just print it.
    # You can test a return value easily, harder to test stdout.
    for item in print_items:
        if "issuer" == item:
            print(f"{orange(f'{item:<{width}}')} : {' '.join(cert.issuer)}")
        elif "chain" == item:
            if len(cert.__getattribute__(item)) > 0:
                print(
                    f"{orange(f'{item:<{width}}')} "
                    f": {orange(' » ').join(cert.__getattribute__(item))}"
                )
        elif "subject" == item:
            cert.subject = [
                f"{c[:5]}{bold(blue(c[5:]))}" if c.endswith(f" {host}") else c
                for c in cert.subject
            ]
            print(f"{orange(f'{item:<{width}}')} : {' '.join(cert.subject)}")
        elif "subject_alt_name" == item:
            for san in sorted(cert.sans):
                if host == str(san) and not matched_host:
                    # Our host arg matches an exact SAN
                    matched_host = True
                    print(f"{orange(f'{item:<{width}}')} : {bold(blue(san))}")
                elif (
                    str(san).endswith(re.sub("^[a-z1-9_-]+", "*", host))
                    and not matched_host
                ):
                    # Our host arg matches a wildcard SAN
                    matched_host = True
                    print(f"{orange(f'{item:<{width}}')} : {orange(san)}")
                else:
                    print(f"{orange(f'{item:<{width}}')} : {san}")
        elif "basic_constraints" == item:
            # Lets highlight any certs which are CAs
            if cert.basic_constraints["ca"] == "True":
                cert.basic_constraints["ca"] = orange("True")
            for item in ["ca", "path_length"]:
                print(f"{orange(f'{item:<{width}}')} : {cert.basic_constraints[item]}")
        elif "serial_number" == item:
            print(
                f"{orange(f'{item:<{width}}')} "
                f": {bold(blue(str(cert.serial_as_hex)))}"
            )
        elif "not_after" == item:
            warning = ""
            if cert.not_after <= helper.today:
                warning = f" {red('(expired!)')}"
            elif cert.not_after <= helper.next_14d:
                warning = f" {red('(expires within 14 days!)')}"
            elif cert.not_after <= helper.next_30d:
                warning = f" {red('(expires within 30 days!)')}"
            elif cert.not_after <= helper.next_90d:
                warning = f" {red('(expires within 90 days!)')}"
            print(f"{orange(f'{item:<{width}}')} : {cert.not_after}" + warning)
        elif "public_key_algorithm" == item:
            print(
                f"{orange(f'{item:<{width}}')} "
                f": {cert.key_type} ({cert.key_bits} bit)"
            )
            if debug:
                print(f"{orange(f'{item:<{width}}')} : Factors: {cert.key_factors}")
        elif "signature_algorithm" == item:
            print(
                f"{orange(f'{item:<{width}}')} "
                f": {cert.sig_algo} params({cert.sig_algo_params})"
            )
        elif "key_usage" in item:
            print(
                f"{orange(f'{item:<{width}}')} "
                f": {', '.join(sorted(cert.__getattribute__(item)))}"
            )
        else:
            print(f"{orange(f'{item:<{width}}')} : {cert.__getattribute__(item)}")
