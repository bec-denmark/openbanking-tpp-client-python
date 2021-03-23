import base64
import hashlib
import re
import uuid

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.asymmetric import padding


class Proxy(object):

    def __init__(self, qwac_cert_file_path, qwac_key_file_path, qseal_cert_file_path, qseal_key_file_path,
                 qseal_key_file_password=None, http_proxy=None, https_proxy=None) -> None:
        super().__init__()
        self.http_proxy = http_proxy
        self.https_proxy = https_proxy
        self.pk_password = qseal_key_file_password
        self.cert = (qwac_cert_file_path, qwac_key_file_path)
        self.qseal_key_file_path = qseal_key_file_path
        qseal_cert_data = self._get_cert_data(qseal_cert_file_path)
        qs_cert_sn = self._get_cert_sn(qseal_cert_data)
        qs_issuer_name = self._get_cert_issuer(qseal_cert_data)
        self.tpp_sig_cert = self._get_certificate(qseal_cert_data)
        self.sig_keyid = "SN=%s,CA=%s" % (qs_cert_sn, qs_issuer_name)
        self.signing_string_template = "digest: %s\nx-request-id: %s"
        self.sig_header_template = "keyId=\"%s\",algorithm=\"rsa-sha256\",headers=\"digest x-request-id\",signature=\"%s\""

    _signing_configs = (
        (dsa.DSAPrivateKey, lambda h: {
            'algorithm': h}),
        (ec.EllipticCurvePrivateKey, lambda h: {
            'signature_algorithm': ec.ECDSA(h)}),
        (rsa.RSAPrivateKey, lambda h: {
            'padding': padding.PKCS1v15(),
            'algorithm': h
        }),
    )

    def _get_certificate(self, cert_data):
        formatted = cert_data.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        cert_str = ""
        for line in formatted.split("\n"):
            if not re.match(r'^-----(BEGIN|END) CERTIFICATE', line):
                cert_str += line
            else:
                if line.startswith('^-----END CERTIFICATE'):
                    break
        return cert_str

    def _get_digest(self, message):
        s256 = hashlib.sha256()
        s256.update(message.encode('utf-8'))
        digest = "SHA-256=" + base64.b64encode(s256.digest()).decode("utf-8")
        return digest

    def _get_cert_data(self, cert_path):
        with open(cert_path, "rb") as cert_file:
            binary_content = cert_file.read()
        return x509.load_pem_x509_certificate(binary_content, default_backend())

    def _get_cert_sn(self, cert_data):
        return hex(cert_data.serial_number).split('x')[-1]

    def _sign(self, private_key, data, algorithm=hashes.SHA256()):
        with open(private_key, 'rb') as private_key:
            key = serialization.load_pem_private_key(
                private_key.read(), self.pk_password, default_backend())

        return key.sign(data, **self._key_singing_config(key, algorithm))

    def _key_singing_config(self, key, hashing_algorithm):
        try:
            factory = next(
                config
                for type_, config in self._signing_configs
                if isinstance(key, type_)
            )
        except StopIteration:
            raise ValueError('Unsupported key type {!r}'.format(type(key)))
        return factory(hashing_algorithm)

    def _get_cert_issuer(self, cert_data):
        return cert_data.issuer.rfc4514_string()

    def proxy_request(self, method, api_url, body="", x_request_id=str(uuid.uuid4())):
        body_digest = self._get_digest(body)
        signing_string = self.signing_string_template % (body_digest, x_request_id)
        raw_signed_string = self._sign(self.qseal_key_file_path, signing_string.encode('utf-8'))
        signed_string = re.sub(r"[\r\n]", "", base64.encodebytes(raw_signed_string).decode())
        sig_header = self.sig_header_template % (self.sig_keyid, signed_string)
        headers = {
            "X-Request-ID": x_request_id,
            "Digest": body_digest,
            "Signature": sig_header,
            "Content-Type": "application/json",
            "TPP-Signature-Certificate": self.tpp_sig_cert
        }

        if self.http_proxy or self.https_proxy:
            proxies = {
                "http": self.http_proxy,
                "https": self.https_proxy
            }
            return requests.request(method, api_url, data=body, verify=False, cert=self.cert, headers=headers, proxies=proxies)

        return requests.request(method, api_url, data=body, verify=False, cert=self.cert, headers=headers)

    def enroll_certificates(self, enrolment_url, ca_interm_file_path, ca_root_file_path, tppId, commercial_name,
                            roles="[ \"PSP_AI\", \"PSP_PI\", \"PSP_IC\", \"PSP_AS\" ]"):
        qwac_cert = self._get_certificate(self._get_cert_data(self.cert[0]))
        ca_cert = self._get_certificate(self._get_cert_data(ca_interm_file_path))
        ca_root = self._get_certificate(self._get_cert_data(ca_root_file_path))
        tpp_sig_cert = self.tpp_sig_cert

        body = '{ "tppid":"%s", "commercialname":"%s", "roles": %s, "qwaccert": { "certificate":"%s", "cacert":"%s", "chaincerts": [ { "cert":"%s" } ] }, "qsealcert":  { "certificate":"%s", "cacert":"%s", "chaincerts": [ { "cert":"%s" } ] }  } ' % \
               (tppId, commercial_name, roles, qwac_cert, ca_cert, ca_root, tpp_sig_cert, ca_cert, ca_root)
        return self.proxy_request("POST", enrolment_url, body)
