"""Persistencia del keystore simulado en keystore.json (Parte A).

Estructura:
{
  "keystore_password": "<hash con sal, nunca la contraseña en claro>",
  "keys": {
    "miAlias": {
      "private_key": "-----BEGIN ENCRYPTED PRIVATE KEY-----...",
      "public_key": "-----BEGIN PUBLIC KEY-----...",
      "dname": "CN=..., OU=..., O=..., L=..., ST=..., C=ES"
    }
  }
}
"""


def load(path: str) -> dict:
    """Lee el keystore del disco.

    Lanza KeystoreNotFoundError si no existe y KeystoreCorruptedError si el
    JSON no es válido.
    """
    raise NotImplementedError


def save(path: str, data: dict) -> None:
    """Escribe el keystore en disco."""
    raise NotImplementedError


def verify_store_password(data: dict, password: str) -> bool:
    """Comprueba la contraseña del almacén contra el hash guardado."""
    raise NotImplementedError


def alias_exists(data: dict, alias: str) -> bool:
    """Indica si el alias ya está en el keystore."""
    raise NotImplementedError


def add_entry(data: dict, alias: str, private_pem: str, public_pem: str, dname: str) -> None:
    """Añade una entrada. Lanza AliasExistsError si el alias ya existe."""
    raise NotImplementedError


def get_entry(data: dict, alias: str) -> dict:
    """Devuelve la entrada del alias. Lanza AliasNotFoundError si no existe."""
    raise NotImplementedError
