from unittest import mock

import pytest
from click.testing import CliRunner

from tlsserial import cli, tlsserial


# We need to mock the helper functions to avoid making network calls
@mock.patch("tlsserial.helper.get_certs_from_host")
@mock.patch("tlsserial.helper.get_certs_from_file")
def test_cli_url(mock_get_certs_from_file, mock_get_certs_from_host):
    runner = CliRunner()
    result = runner.invoke(cli.main, ["--url", "example.com"])
    assert result.exit_code == 0
    mock_get_certs_from_host.assert_called_once()
    mock_get_certs_from_file.assert_not_called()


@mock.patch("tlsserial.helper.get_certs_from_host")
@mock.patch("tlsserial.helper.get_certs_from_file")
def test_cli_file(mock_get_certs_from_file, mock_get_certs_from_host):
    runner = CliRunner()
    result = runner.invoke(cli.main, ["--file", "test.pem"])
    assert result.exit_code == 0
    mock_get_certs_from_file.assert_called_once()
    mock_get_certs_from_host.assert_not_called()


@mock.patch("tlsserial.helper.get_certs_from_host")
@mock.patch("tlsserial.helper.get_certs_from_file")
def test_cli_no_args(mock_get_certs_from_file, mock_get_certs_from_host):
    runner = CliRunner()
    result = runner.invoke(cli.main)
    assert result.exit_code == 0
    mock_get_certs_from_file.assert_not_called()
    mock_get_certs_from_host.assert_not_called()


@mock.patch("tlsserial.helper.get_certs_from_host")
def test_handle_url(mock_get_certs_from_host):
    mock_get_certs_from_host.return_value = ([mock.MagicMock()], "SSL cert")
    tlsserial.handle_url("example.com")
    mock_get_certs_from_host.assert_called_once_with("example.com", 443)


@mock.patch("tlsserial.helper.get_certs_from_file")
def test_handle_file(mock_get_certs_from_file):
    mock_get_certs_from_file.return_value = ([mock.MagicMock()], "SSL cert")
    tlsserial.handle_file("test.pem")
    mock_get_certs_from_file.assert_called_once_with("test.pem")


def test_get_args():
    assert tlsserial.get_args("example.com") == ("example.com", 443)
    assert tlsserial.get_args("example.com:8080") == ("example.com", "8080")
    with pytest.raises(SystemExit):
        tlsserial.get_args("invalid input")


# NOTE: Parametrized test cases allow you to use lots of examples


@pytest.mark.parametrize(
    "input_str, expected",
    [
        ("example.com", ("example.com", 443)),
        ("example.com:8080", ("example.com", "8080")),
        ("http://example.com:8080", ("example.com", "8080")),
        ("https://example.com:8080", ("example.com", "8080")),
        ("ldaps://example.com:8080", ("example.com", "8080")),
    ],
)
def test_get_args_success(input_str, expected):
    assert tlsserial.get_args(input_str) == expected


def test_get_args_failure():
    with pytest.raises(SystemExit):
        tlsserial.get_args("invalid input")
