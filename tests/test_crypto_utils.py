"""
Pruebas del módulo crypto_utils.py (Parte B).

Cómo ejecutarlas (desde la carpeta del proyecto):
    python3 -m unittest discover tests -v
"""

import os
import sys
import unittest

# Permite importar crypto_utils.py y errors.py, que están en la carpeta de arriba.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

import crypto_utils
from errors import WrongPasswordError

PASSWORD = "secreto123"
DNAME = {"CN": "Ana Perez", "OU": "IT", "O": "Empresa", "L": "Madrid", "ST": "Madrid", "C": "ES"}


class PruebasCrypto(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Generar una clave RSA tarda un momento: se hace una sola vez para todas las pruebas.
        cls.key = crypto_utils.generate_keypair()

    def test_clave_rsa_de_2048_bits(self):
        self.assertEqual(self.key.key_size, 2048)

    def test_clave_publica_en_pem(self):
        pem = crypto_utils.public_key_to_pem(self.key)
        self.assertIsInstance(pem, str)
        self.assertTrue(pem.startswith("-----BEGIN PUBLIC KEY-----"))

    def test_clave_privada_va_cifrada(self):
        pem = crypto_utils.private_key_to_pem(self.key, PASSWORD)
        self.assertIsInstance(pem, str)
        self.assertTrue(pem.startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----"))

    def test_privada_ida_y_vuelta(self):
        pem = crypto_utils.private_key_to_pem(self.key, PASSWORD)
        recovered = crypto_utils.private_key_from_pem(pem, PASSWORD)
        self.assertEqual(
            crypto_utils.public_key_to_pem(recovered),
            crypto_utils.public_key_to_pem(self.key),
        )

    def test_contrasena_incorrecta(self):
        pem = crypto_utils.private_key_to_pem(self.key, PASSWORD)
        with self.assertRaises(WrongPasswordError):
            crypto_utils.private_key_from_pem(pem, "otra-contrasena")

    def test_csr_es_pem_y_bytes(self):
        csr_pem = crypto_utils.build_csr(self.key, DNAME)
        self.assertIsInstance(csr_pem, bytes)
        self.assertTrue(csr_pem.startswith(b"-----BEGIN CERTIFICATE REQUEST-----"))

    def test_csr_contiene_el_dn(self):
        csr = x509.load_pem_x509_csr(crypto_utils.build_csr(self.key, DNAME))
        self.assertEqual(csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, "Ana Perez")
        self.assertEqual(csr.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value, "ES")

    def test_csr_tiene_firma_valida(self):
        csr = x509.load_pem_x509_csr(crypto_utils.build_csr(self.key, DNAME))
        self.assertTrue(csr.is_signature_valid)

    def test_csr_lleva_la_clave_publica_y_nunca_la_privada(self):
        csr_pem = crypto_utils.build_csr(self.key, DNAME)
        self.assertNotIn(b"PRIVATE KEY", csr_pem)
        csr = x509.load_pem_x509_csr(csr_pem)
        public_in_csr = csr.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        self.assertEqual(public_in_csr, crypto_utils.public_key_to_pem(self.key))

    def test_csr_omite_campos_vacios_o_ausentes(self):
        dname = {"CN": "Ana Perez", "OU": "", "C": "ES"}
        csr = x509.load_pem_x509_csr(crypto_utils.build_csr(self.key, dname))
        self.assertEqual(csr.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME), [])

    def test_csr_sin_datos_da_error(self):
        with self.assertRaises(ValueError):
            crypto_utils.build_csr(self.key, {})


if __name__ == "__main__":
    unittest.main()
