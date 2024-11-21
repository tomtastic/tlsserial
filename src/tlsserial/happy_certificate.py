from dataclasses import dataclass
from typing import Any, Dict, List

import pendulum
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import ExtensionNotFound
from cryptography.x509.oid import ExtensionOID, NameOID

NAME_ATTRIBS = [
    ("CN", NameOID.COMMON_NAME),
    ("O", NameOID.ORGANIZATION_NAME),
    ("OU", NameOID.ORGANIZATIONAL_UNIT_NAME),
    ("L", NameOID.LOCALITY_NAME),
    ("ST", NameOID.STATE_OR_PROVINCE_NAME),
    ("C", NameOID.COUNTRY_NAME),
    ("DC", NameOID.DOMAIN_COMPONENT),
    ("E", NameOID.EMAIL_ADDRESS),
]

@dataclass
class HappyCertificate:
    """HappyCertificate is a happy certificate."""

    cert: x509.Certificate


    @property
    def version(self) -> int:
        """Return the x509 version."""
        return self.cert.version.value + 1

    @property
    def issuer(self) -> list[str]:
        """Issuer."""
        return [
            f"[{a}] {n.value}"
            for a, b in NAME_ATTRIBS
            for n in self.cert.issuer.get_attributes_for_oid(b)
        ]

    @property
    def subject(self) -> List[str]:
        """Subject."""
        return [
            f"[{a}] {n.value}"
            for a, b in NAME_ATTRIBS
            for n in self.cert.subject.get_attributes_for_oid(b)
        ]

    @property
    def sans(self) -> list[Any]:
        """The Subject Alternative Names."""
        try:
            return self.cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value.get_values_for_type(x509.DNSName)
        except ExtensionNotFound:
            return []

    @property
    def basic_constraints(self) -> Dict[str, str]:
        """Return the CA BasicConstraint properties."""
        basic_constraints: Dict[str, str] = {}
        try:
            basic_constraints_object = self.cert.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            ).value
            basic_constraints["ca"] = str(basic_constraints_object.ca)
            basic_constraints["path_length"] = str(
                basic_constraints_object.path_length
            )
        except (ValueError, ExtensionNotFound):
            pass
        return basic_constraints

    @property
    def key_usage(self) -> list[str]:
        """Key usage."""
        key_usage = []
        try:
            key_usage_object = self.cert.extensions.get_extension_for_oid(
                ExtensionOID.KEY_USAGE
            ).value
            for attr, value in key_usage_object.__dict__.items():
                if value is True:
                    key_usage.append(attr.lstrip("_"))
        except (UnboundLocalError, ValueError, ExtensionNotFound):
            pass
        return key_usage

    @property
    def ext_key_usage(self) -> list[str]:
        """Returns list of Extended key usages."""
        ext_key_usage = []
        try:
            ext_key_usage_object = self.cert.extensions.get_extension_for_oid(
                ExtensionOID.EXTENDED_KEY_USAGE
            ).value
            for usage in ext_key_usage_object.__dict__["_usages"]:
                ext_key_usage.append(usage._name)
        except (UnboundLocalError, ValueError, ExtensionNotFound):
            pass
        return ext_key_usage

    @property
    def before_and_after(self) -> tuple:
        """Returns tuple of not_after and not_before datetimes."""
        not_after = pendulum.parse(self.cert.not_valid_after.isoformat())
        not_before = pendulum.parse(self.cert.not_valid_before.isoformat())
        return not_before, not_after

    @property
    def crls(self) -> str:
        """Returns CRLs."""
        crls = ""
        try:
            crl_distribution_points = [
                crl_dp.full_name
                for crl_dp in self.cert.extensions.get_extension_for_oid(
                    ExtensionOID.CRL_DISTRIBUTION_POINTS
                ).value
            ]
            crls = " ".join(
                crl.value for crl_list in crl_distribution_points for crl in crl_list
            )
        except (ValueError, ExtensionNotFound):
            pass
        return crls

    @property
    def ocsp_and_caissuer(self) -> tuple:
        """Returns tuple of OCSP and CA Issuers locations."""
        ocsp = ""
        ca_issuers = ""
        try:
            authorityInfoAccess = self.cert.extensions.get_extension_for_oid(
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

    @property
    def key_type(self):
        """Return the public key type (eg. RSA/DSA/etc)."""
        public_key = self.cert.public_key()
        key_type = f"{type(public_key).__name__.lstrip('_')}"
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            key_type += f" {public_key.public_numbers().curve.name}"
        return key_type

    @property
    def key_bits(self) -> int:
        """Returns the bit length of the public key."""
        key_bits = 0
        public_key = self.cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            key_bits = public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_bits = public_key.key_size
        return key_bits

    @property
    def key_factors(self) -> dict:
        """Returns dict w/ modulus size and exponent from public key bits."""
        """or other key factors where appropriate"""
        key_factors: Dict[str, int] = {}
        public_key = self.cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            key_factors["exponent"] = public_key.public_numbers().e
            key_factors["n"] = public_key.public_numbers().n
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_factors["x"] = public_key.public_numbers().x
            key_factors["y"] = public_key.public_numbers().y
        return key_factors

    @property
    def sig_algorithm(self) -> str | None:
        """Return the signature algorithm."""
        if isinstance(self.cert.signature_hash_algorithm, hashes.HashAlgorithm):
            sig_algo = self.cert.signature_algorithm_oid._name
        else:
            sig_algo = None
        return sig_algo

    @property
    def sig_algorithm_params(self) -> str:
        """Return the signature algorithm parameters."""
        pss = self.cert.signature_algorithm_parameters
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
