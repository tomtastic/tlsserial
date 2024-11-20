from dataclasses import dataclass, field

import pendulum
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from tlsserial.happy_certificate import HappyCertificate


@pytest.fixture
def test_cert() -> x509.Certificate:
    """Load a test certificate."""
    with open("test_cert.pem", "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    return cert

def test_happy_certificate(test_cert):
    """Test the HappyCertificate class."""
    happy_cert = HappyCertificate(test_cert)

    assert happy_cert.version == 3
    assert isinstance(happy_cert.issuer, list)
    assert "[CN] localhost" in happy_cert.issuer
    assert isinstance(happy_cert.subject, list)
    assert "[CN] localhost" in happy_cert.subject
    assert isinstance(happy_cert.sans, list)
    # Add assertions for sans based on test_cert

    assert isinstance(happy_cert.basic_constraints, dict)
    # Add assertions for basic_constraints based on test_cert

    assert isinstance(happy_cert.key_usage, list)
    # Add assertions for key_usage based on test_cert

    assert isinstance(happy_cert.ext_key_usage, list)
    # Add assertions for ext_key_usage based on test_cert

    not_before, not_after = happy_cert.before_and_after
    assert isinstance(not_before, pendulum.DateTime)
    assert isinstance(not_after, pendulum.DateTime)
    assert not_before < not_after

    assert isinstance(happy_cert.crls, str)
    # Add assertions for crls based on test_cert

    ocsp, ca_issuers = happy_cert.ocsp_and_caissuer
    assert isinstance(ocsp, str)
    assert isinstance(ca_issuers, str)
    # Add assertions for ocsp and ca_issuers based on test_cert

    assert isinstance(happy_cert.key_type, str)
    # Add assertions for key_type based on test_cert

    assert isinstance(happy_cert.key_bits, int)
    # Add assertions for key_bits based on test_cert

    assert isinstance(happy_cert.key_factors, dict)
    # Add assertions for key_factors based on test_cert

    assert isinstance(happy_cert.sig_algorithm, str)
    # Add assertions for sig_algorithm based on test_cert

    assert isinstance(happy_cert.sig_algorithm_params, str)
    # Add assertions for sig_algorithm_params based on test_cert

    assert print(happy_cert) == 'foo' 