"""Operaciones criptográficas del simulador (Parte B).

Todas las claves y solicitudes se intercambian con el resto del programa como
texto PEM, para poder guardarlas directamente en keystore.json.

PEM es un formato de texto: los bytes binarios de la clave se codifican en
Base64 y se envuelven entre líneas "-----BEGIN ...-----" y "-----END ...-----".
"""

import datetime
import hashlib
import os
import struct
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import NameOID

from errors import KeystoreCorruptedError, WrongPasswordError

# Tamaño de clave que pide el enunciado.
KEY_SIZE = 2048

# Exponente público estándar de RSA (65537 = 2^16 + 1). Es primo y su forma
# binaria tiene solo dos bits a 1, lo que hace rápida la operación pública.
PUBLIC_EXPONENT = 65537

# Partes del DN en el orden en que se escriben, con su identificador X.509.
_DNAME_OIDS = [
    ("CN", NameOID.COMMON_NAME),
    ("OU", NameOID.ORGANIZATIONAL_UNIT_NAME),
    ("O", NameOID.ORGANIZATION_NAME),
    ("L", NameOID.LOCALITY_NAME),
    ("ST", NameOID.STATE_OR_PROVINCE_NAME),
    ("C", NameOID.COUNTRY_NAME),
]


def generate_keypair() -> RSAPrivateKey:
    """Genera un par de claves RSA de 2048 bits.

    El objeto devuelto es la clave privada; de ella se obtiene la pública
    con key.public_key().
    """
    return rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=KEY_SIZE)


def private_key_to_pem(key: RSAPrivateKey, password: str) -> str:
    """Serializa la clave privada en PEM, cifrada con la contraseña del alias.

    PKCS#8 es el formato estándar para claves privadas. BestAvailableEncryption
    elige el mejor algoritmo de cifrado simétrico disponible y deriva la clave
    de cifrado a partir de la contraseña. Pide la contraseña como bytes.
    """
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
    )
    return pem.decode("ascii")


def private_key_from_pem(pem: str, password: str) -> RSAPrivateKey:
    """Carga una clave privada desde PEM cifrado.

    Lanza WrongPasswordError si la contraseña no es correcta (o si el PEM
    está dañado, porque la librería no distingue ambos casos) y
    KeystoreCorruptedError si la clave guardada no está cifrada.
    """
    try:
        return serialization.load_pem_private_key(
            pem.encode("ascii"),
            password=password.encode("utf-8"),
        )
    except ValueError:
        raise WrongPasswordError("Contraseña de la clave incorrecta.") from None
    except TypeError:
        # La librería lo lanza si le damos contraseña y la clave no está cifrada.
        raise KeystoreCorruptedError("La clave guardada no está cifrada: el almacén está dañado.") from None


def public_key_to_pem(key: RSAPrivateKey) -> str:
    """Devuelve la clave pública asociada en formato PEM.

    SubjectPublicKeyInfo es el formato estándar X.509 para claves públicas
    ("BEGIN PUBLIC KEY"). La clave pública no necesita cifrarse.
    """
    pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("ascii")


def build_csr(key: RSAPrivateKey, dname: dict) -> bytes:
    """Crea una solicitud de firma de certificado (CSR) en PEM.

    dname: diccionario con las claves CN, OU, O, L, ST, C. Las que falten o
    estén vacías se omiten (X.509 no admite atributos vacíos).

    El CSR contiene la clave pública y el DN, y se firma con la clave privada
    para demostrar que quien lo solicita la posee. La privada nunca se incluye.
    """
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(_build_name(dname))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def _build_name(dname: dict) -> x509.Name:
    """Convierte el diccionario del DN en un x509.Name, omitiendo campos vacíos."""
    attributes = []
    for field, oid in _DNAME_OIDS:
        value = dname.get(field, "")
        if value != "":
            attributes.append(x509.NameAttribute(oid, value))

    if not attributes:
        raise ValueError("El DN no tiene ningún dato: no se puede crear el certificado.")
    return x509.Name(attributes)


def build_self_signed_cert(key: RSAPrivateKey, dname: dict, days: int = 365) -> bytes:
    """Crea un certificado autofirmado en PEM, válido durante `days` días.

    Autofirmado significa que el emisor y el titular son la misma entidad: se
    firma con la propia clave privada. Es lo que genera `keytool -genkeypair`
    junto al par de claves. Ninguna CA lo avala, así que no ofrece confianza
    de terceros por defecto.
    """
    if days <= 0:
        raise ValueError("Los días de validez deben ser un número positivo.")

    name = _build_name(dname)  # titular y emisor son el mismo
    now = datetime.datetime.now(datetime.timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def _der_length(length: int) -> bytes:
    """Longitud en formato DER (1 byte si es < 128; si no, 0x80+nº de bytes y los bytes)."""
    if length < 0x80:
        return bytes([length])
    length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 + len(length_bytes)]) + length_bytes


def _jks_protect_key(pkcs8_der: bytes, password: str) -> bytes:
    """Cifra la clave privada como lo hace el JKS de Sun (EncryptedPrivateKeyInfo).

    El algoritmo (OID 1.3.6.1.4.1.42.2.17.1.1) es propio de Sun: genera un flujo
    de bytes con SHA-1 a partir de la contraseña y una sal, y lo suma por XOR a
    la clave. Al final añade un SHA-1 de control para detectar contraseñas malas.
    """
    password_bytes = password.encode("utf-16-be")
    salt = os.urandom(20)

    # Flujo de bloques: SHA1(pass+sal), SHA1(pass+bloque anterior), ...
    keystream = b""
    block = salt
    while len(keystream) < len(pkcs8_der):
        block = hashlib.sha1(password_bytes + block).digest()
        keystream += block

    encrypted = bytes(a ^ b for a, b in zip(pkcs8_der, keystream))
    check = hashlib.sha1(password_bytes + pkcs8_der).digest()
    payload = salt + encrypted + check

    algorithm = b"\x30\x0e\x06\x0a\x2b\x06\x01\x04\x01\x2a\x02\x11\x01\x01\x05\x00"
    octet_string = b"\x04" + _der_length(len(payload)) + payload
    body = algorithm + octet_string
    return b"\x30" + _der_length(len(body)) + body


def build_jks(alias: str, key: RSAPrivateKey, cert_pem: bytes, password: str) -> bytes:
    """Crea un almacén JKS (formato clásico de Java) con un único alias.

    El JKS guarda la clave privada junto a su certificado. `password` se usa
    como contraseña del almacén y de la clave, igual que hace keytool por
    defecto. Como keytool, el alias se guarda en minúsculas. Se escribe a mano
    porque `cryptography` no sabe crear JKS.
    """
    pkcs8_der = key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_der = x509.load_pem_x509_certificate(cert_pem).public_bytes(serialization.Encoding.DER)
    alias_bytes = alias.lower().encode("utf-8")
    key_blob = _jks_protect_key(pkcs8_der, password)

    # Cabecera: magia 0xFEEDFEED, versión 2, una entrada.
    data = struct.pack(">III", 0xFEEDFEED, 2, 1)
    # Entrada: tipo 1 = clave privada, alias, fecha (ms), clave cifrada y cadena de 1 certificado.
    data += struct.pack(">I", 1)
    data += struct.pack(">H", len(alias_bytes)) + alias_bytes
    data += struct.pack(">Q", int(time.time() * 1000))
    data += struct.pack(">I", len(key_blob)) + key_blob
    data += struct.pack(">I", 1)
    data += struct.pack(">H", 5) + b"X.509"
    data += struct.pack(">I", len(cert_der)) + cert_der
    # Firma de integridad del almacén con la contraseña.
    data += hashlib.sha1(password.encode("utf-16-be") + b"Mighty Aphrodite" + data).digest()
    return data


def certificate_fingerprint(cert_pem: bytes) -> str:
    """Huella SHA-256 del certificado, como la muestra `keytool -list`.

    Devuelve pares hexadecimales en mayúsculas separados por ':'
    (por ejemplo 'A1:B2:...'). Sirve para comprobar a ojo que dos
    certificados son el mismo.
    """
    cert = x509.load_pem_x509_certificate(cert_pem)
    return cert.fingerprint(hashes.SHA256()).hex(":").upper()
