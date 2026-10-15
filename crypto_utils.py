"""Operaciones criptográficas del simulador (Parte B).

Todas las claves y solicitudes se intercambian con el resto del programa como
texto PEM, para poder guardarlas directamente en keystore.json.

PEM es un formato de texto: los bytes binarios de la clave se codifican en
Base64 y se envuelven entre líneas "-----BEGIN ...-----" y "-----END ...-----".
"""

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import NameOID

from errors import WrongPasswordError

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
    está dañado, porque la librería no distingue ambos casos).
    """
    try:
        return serialization.load_pem_private_key(
            pem.encode("ascii"),
            password=password.encode("utf-8"),
        )
    except ValueError:
        raise WrongPasswordError("Contraseña de la clave incorrecta.") from None


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
    attributes = []
    for field, oid in _DNAME_OIDS:
        value = dname.get(field, "")
        if value != "":
            attributes.append(x509.NameAttribute(oid, value))

    if not attributes:
        raise ValueError("El DN no tiene ningún dato: no se puede crear el CSR.")

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name(attributes))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)
