import ssl
import sys
import datetime
from functools import partial
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from ipaddress import ip_address
from util.x509_constant import algorithm_for_sign, eku_is_critical, bc_is_critical, \
    san_is_critical, key_usage_is_critical, key_usage_extension, authority_key_is_critical, \
    certificate_policies_is_critical, subject_key_is_critical, \
    bc_extension, eku_extension, certificate_policies_extension


# to-do: 1.use asterisk and 2.merge key/cert and 3.save ctx for optimizing.
class InstantCertServerSideCtx:
    def __init__(self, issuer_full_chain_cert_path, issuer_private_key_path, issuer_private_key_pass: bytes | None,
                 instant_certificate_temp_file_path, max_san_list_size=1024):
        self.common_name = "*.google.com"
        self.max_san_list_size = max_san_list_size
        self.san_list = [x509.DNSName(self.common_name)]
        self.last_added_san_index = 0
        self.cert_not_valid_before: datetime.datetime | None = None
        self.cert_not_valid_after: datetime.datetime | None = None

        self.instant_certificate_saved_path = instant_certificate_temp_file_path
        with open(issuer_private_key_path, "rb") as f:
            issuer_pem_private_key = f.read()
        with open(issuer_full_chain_cert_path, "rb") as f:
            issuer_pem_x509_full_chain_certs = f.read()

        self.issuer_private_key = serialization.load_pem_private_key(issuer_pem_private_key, issuer_private_key_pass)
        issuer_full_chain_certs_list = x509.load_pem_x509_certificates(issuer_pem_x509_full_chain_certs)
        issuer_certificate = issuer_full_chain_certs_list[0]
        self.ancestor_pem_certs = b""
        for iter_cert in issuer_full_chain_certs_list:
            self.ancestor_pem_certs += iter_cert.public_bytes(serialization.Encoding.PEM)

        subject_private_key = ec.generate_private_key(ec.SECP256R1())
        self.private_key_bytes = subject_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())
        subject_public_key = subject_private_key.public_key()
        subject_key_extension = x509.SubjectKeyIdentifier.from_public_key(subject_public_key)

        authority_key_extension = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            issuer_certificate.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier).value)
        alt_authority_key_extension = x509.AuthorityKeyIdentifier.from_issuer_public_key(
            issuer_certificate.public_key())
        if authority_key_extension != alt_authority_key_extension:
            sys.exit("Authority key extension mismatch")

        if not issuer_certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            sys.exit("issuer certificate must be CA")
        check_ku = issuer_certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        if (not check_ku.key_cert_sign) or (not check_ku.crl_sign):
            sys.exit("issuer certificate Key-Usage must have Certificate-Signing and CRL-Signing")

        subject_n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.common_name)])

        self.cert_builder = x509.CertificateBuilder().subject_name(subject_n).issuer_name(
            issuer_certificate.subject).public_key(
            subject_public_key).add_extension(
            bc_extension, critical=bc_is_critical).add_extension(
            key_usage_extension, critical=key_usage_is_critical).add_extension(
            eku_extension, critical=eku_is_critical).add_extension(
            subject_key_extension, critical=subject_key_is_critical).add_extension(
            authority_key_extension, critical=authority_key_is_critical).add_extension(
            certificate_policies_extension, critical=certificate_policies_is_critical)
        self.create_instant_certificate()

    def create_instant_certificate(self):
        san_extension = x509.SubjectAlternativeName(self.san_list)
        cert_serial_number = x509.random_serial_number()
        now_time = datetime.datetime.now(datetime.timezone.utc)
        self.cert_not_valid_before = now_time - datetime.timedelta(days=3)
        self.cert_not_valid_after = now_time + datetime.timedelta(days=360)

        cert = self.cert_builder.serial_number(cert_serial_number).not_valid_before(
            self.cert_not_valid_before).not_valid_after(self.cert_not_valid_after).add_extension(
            san_extension, critical=san_is_critical).sign(
            self.issuer_private_key, algorithm_for_sign)

        pure_primary_pem_cert = cert.public_bytes(serialization.Encoding.PEM)

        with open(self.instant_certificate_saved_path, "wb") as f:
            f.write(self.private_key_bytes + pure_primary_pem_cert + self.ancestor_pem_certs)

    def add_to_san_list(self, new_san):
        if len(self.san_list) < self.max_san_list_size:
            self.san_list.append(new_san)
            self.last_added_san_index += 1
            if len(self.san_list) != (self.last_added_san_index + 1):
                sys.exit()
        else:
            if len(self.san_list) > self.max_san_list_size:
                sys.exit()
            self.last_added_san_index = (self.last_added_san_index + 1) % self.max_san_list_size
            if self.last_added_san_index == 0:
                self.last_added_san_index = 1
            self.san_list[self.last_added_san_index] = new_san

    def _get_server_side_ctx(self, alpn: str | None) -> ssl.SSLContext:
        new_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
        if alpn is not None:
            new_context.set_alpn_protocols((alpn,))
        else:
            new_context.set_alpn_protocols(())
        new_context.sni_callback = partial(self.sni_callback, alpn)
        new_context.load_cert_chain(self.instant_certificate_saved_path)
        return new_context

    def update_cert(self, v_type, value):
        if (v_type == "ipv4") or (v_type == "ipv6"):
            new_san = x509.IPAddress(ip_address(value))
        elif v_type == "hostname":
            new_san = x509.DNSName(value)
        else:
            sys.exit()

        if new_san in self.san_list:
            now_time = datetime.datetime.now(datetime.timezone.utc)
            if now_time < (self.cert_not_valid_after - datetime.timedelta(days=10)):
                return False
            self.create_instant_certificate()
            return True
        self.add_to_san_list(new_san)
        self.create_instant_certificate()
        return True

    def update_cert_and_get_server_side_ctx(self, v_type, value, alpn: str | None) -> ssl.SSLContext:
        self.update_cert(v_type, value)
        return self._get_server_side_ctx(alpn)

    def sni_callback(self, alpn, ssl_sock: ssl.SSLObject, sni: str | None, o_ctx: ssl.SSLContext):
        if sni is not None:
            ssl_sock.context = self.update_cert_and_get_server_side_ctx("hostname", sni, alpn)


def get_client_side_ctx(check_hostname, verify_mode, cadata, alpn) -> ssl.SSLContext:
    if (verify_mode != ssl.CERT_NONE) and (cadata is not None):
        out_ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cadata=cadata)
    else:
        if verify_mode != ssl.CERT_NONE:
            out_ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        else:
            out_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    out_ctx.check_hostname = check_hostname
    out_ctx.verify_mode = verify_mode
    if alpn is None:
        alpn_protocols = ()
    elif type(alpn) is str:
        alpn_protocols = (alpn,)
    else:
        alpn_protocols = alpn
    out_ctx.set_alpn_protocols(alpn_protocols)
    return out_ctx
