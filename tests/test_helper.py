from unittest import mock

from cryptography.hazmat.primitives.asymmetric import padding

from tlsserial import helper


def test_timethis():
    @helper.timethis
    def func():
        pass

    func()


@mock.patch("tlsserial.helper.socket.create_connection")
def test_get_certs_from_host_success(mock_create_connection):
    mock_socket = mock.MagicMock()
    mock_socket._sslobj = mock.MagicMock()
    mock_socket._sslobj.get_verified_chain.return_value = []
    mock_socket.getpeercert.return_value = b"cert"
    mock_create_connection.return_value = mock_socket
    certs, msg = helper.get_certs_from_host("example.com")
    assert certs is not None
    assert msg == "SSL certificate"


@mock.patch("tlsserial.helper.socket.create_connection")
def test_get_certs_from_host_failure(mock_create_connection):
    mock_create_connection.side_effect = Exception("Error")
    certs, msg = helper.get_certs_from_host("example.com")
    assert certs is None
    assert msg == "Error"


@mock.patch("tlsserial.helper.open")
def test_get_certs_from_file_success(mock_open):
    mock_open.return_value = mock.MagicMock()
    mock_open.return_value.__enter__.return_value.read.return_value = "cert"
    certs, msg = helper.get_certs_from_file("test.pem")
    assert certs is not None
    assert msg == "SSL certificate"


@mock.patch("tlsserial.helper.open")
def test_get_certs_from_file_failure(mock_open):
    mock_open.side_effect = FileNotFoundError("Error")
    certs, msg = helper.get_certs_from_file("test.pem")
    assert certs is None
    assert msg == "Error"


def test_get_version():
    cert = mock.MagicMock()
    cert.version.value = 1
    assert helper.get_version(cert) == 2


def test_get_issuer():
    cert = mock.MagicMock()
    cert.issuer.get_attributes_for_oid.return_value = [mock.MagicMock()]
    assert helper.get_issuer(cert) == ["[CN] value"]


def test_get_subject():
    cert = mock.MagicMock()
    cert.subject.get_attributes_for_oid.return_value = [mock.MagicMock()]
    assert helper.get_subject(cert) == ["[CN] value"]


def test_get_sans():
    cert = mock.MagicMock()
    cert.extensions.get_extension_for_oid.return_value.value.get_values_for_type.return_value = [
        "example.com"
    ]
    assert helper.get_sans(cert) == ["example.com"]


def test_get_basic_constraints():
    cert = mock.MagicMock()
    cert.extensions.get_extension_for_oid.return_value.value.ca = True
    cert.extensions.get_extension_for_oid.return_value.value.path_length = 1
    assert helper.get_basic_constraints(cert) == {"ca": "True", "path_length": "1"}


def test_get_key_usage():
    cert = mock.MagicMock()
    cert.extensions.getextension_for_oid.return_value.value.__dict__ = {
        "_digital_signature": True
    }
    assert helper.get_key_usage(cert) == ["digital_signature"]


def test_get_ext_key_usage():
    cert = mock.MagicMock()
    cert.extensions.get_extension_for_oid.return_value.value.__dict__ = {
        "_usages": [mock.MagicMock()]
    }
    cert.extensions.get_extension_for_oid.return_value.value._usages[
        0
    ]._name = "serverAuth"
    assert helper.get_ext_key_usage(cert) == ["serverAuth"]


def test_get_before_and_after():
    cert = mock.MagicMock()
    cert.not_valid_after = mock.MagicMock()
    cert.not_valid_before = mock.MagicMock()
    cert.not_valid_after.isoformat.return_value = "2024-01-01T00:00:00"
    cert.not_valid_before.isoformat.return_value = "2023-01-01T00:00:00"
    assert helper.get_before_and_after(cert) == (mock.ANY, mock.ANY)


def test_get_crls():
    cert = mock.MagicMock()
    cert.extensions.get_extension_for_oid.return_value.value = [mock.MagicMock()]
    cert.extensions.get_extension_for_oid.return_value.value[0].full_name = [
        mock.MagicMock()
    ]
    cert.extensions.get_extension_for_oid.return_value.value[0].full_name[
        0
    ].value = "http://example.com/crl"
    assert helper.get_crls(cert) == "http://example.com/crl"


def test_get_ocsp_and_caissuer():
    cert = mock.MagicMock()
    cert.extensions.get_extension_for_oid.return_value.value = [mock.MagicMock()]
    cert.extensions.get_extension_for_oid.return_value.value[
        0
    ].access_method._name = "OCSP"
    cert.extensions.get_extension_for_oid.return_value.value[
        0
    ].access_location._value = "http://example.com/ocsp"
    assert helper.get_ocsp_and_caissuer(cert) == ("http://example.com/ocsp", "")


def test_get_key_type():
    cert = mock.MagicMock()
    cert.public_key.return_value = mock.MagicMock()
    cert.public_key.return_value.__class__.__name__ = "RSAPublicKey"
    assert helper.get_key_type(cert) == "RSAPublicKey"


def test_get_key_bits():
    cert = mock.MagicMock()
    cert.public_key.return_value = mock.MagicMock()
    cert.public_key.return_value.key_size = 2048
    assert helper.get_key_bits(cert) == 2048


def test_get_key_factors():
    cert = mock.MagicMock()
    cert.public_key.return_value = mock.MagicMock()
    cert.public_key.return_value.public_numbers.return_value = mock.MagicMock()
    cert.public_key.return_value.public_numbers.return_value.e = 65537
    cert.public_key.return_value.public_numbers.return_value.n = 123456789
    assert helper.get_key_factors(cert) == {"exponent": 65537, "n": 123456789}


def test_get_sig_algorithm():
    cert = mock.MagicMock()
    cert.signature_algorithm_oid._name = "sha256WithRSAEncryption"
    assert helper.get_sig_algorithm(cert) == "sha256WithRSAEncryption"


def test_get_sig_algorithm_params():
    cert = mock.MagicMock()
    cert.signature_algorithm_parameters = mock.MagicMock()
    cert.signature_algorithm_parameters.__class__ = padding.PSS
    assert helper.get_sig_algorithm_params() == "PSS"
