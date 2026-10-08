"""Operaciones criptográficas del simulador (Parte B).

Todas las claves y solicitudes se intercambian con el resto del programa como
texto PEM, para poder guardarlas directamente en keystore.json.
"""

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey


def generate_keypair() -> RSAPrivateKey:
    """Genera un par de claves RSA de 2048 bits."""
    raise NotImplementedError


def private_key_to_pem(key: RSAPrivateKey, password: str) -> str:
    """Serializa la clave privada en PEM, cifrada con la contraseña del alias."""
    raise NotImplementedError


def private_key_from_pem(pem: str, password: str) -> RSAPrivateKey:
    """Carga una clave privada desde PEM cifrado.

    Debe lanzar errors.WrongPasswordError si la contraseña no es correcta.
    """
    raise NotImplementedError


def public_key_to_pem(key: RSAPrivateKey) -> str:
    """Devuelve la clave pública asociada en formato PEM."""
    raise NotImplementedError


def build_csr(key: RSAPrivateKey, dname: dict) -> bytes:
    """Crea una solicitud de firma (CSR) en PEM.

    dname: claves CN, OU, O, L, ST, C. Se firma con la clave privada.
    """
    raise NotImplementedError
