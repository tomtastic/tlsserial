import socket
import sys
import logging
from OpenSSL import SSL, crypto
import certifi

hostname = "www.google.com"
port = 443

methods = [
    (SSL.SSLv23_METHOD, "SSL.SSLv23_METHOD"),
    (SSL.TLSv1_METHOD, "SSL.TLSv1_METHOD"),
    (SSL.TLSv1_1_METHOD, "SSL.TLSv1_1_METHOD"),
    (SSL.TLSv1_2_METHOD, "SSL.TLSv1_2_METHOD"),
]

for method, method_name in methods:
    try:
        print(f"\n-- Method {method_name}")
        context = SSL.Context(method=method)
        context.load_verify_locations(cafile=certifi.where())

        conn = SSL.Connection(
            context, socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        )
        conn.settimeout(5)
        conn.connect((hostname, port))
        conn.setblocking(1)
        conn.do_handshake()
        conn.set_tlsext_host_name(hostname.encode())
        chain = conn.get_peer_cert_chain()

        def decode(x: crypto.X509Name) -> str:
            return "/".join(
                ["=".join(z.decode("utf-8") for z in y) for y in x.get_components()]
            )

        if chain:
            for idx, cert in enumerate(chain):
                print(f"{idx} subject: {decode(cert.get_subject())}")
                print(f"  issuer: {decode(cert.get_issuer())})")
                print(f"  serial: {cert.get_serial_number()}")
                print(f'  fingerprint: {cert.digest("sha1")}')

        conn.close()
    except SSL.Error:
        logging.error(f"<><> Method {method_name} failed due to {sys.exc_info()[0]}")
