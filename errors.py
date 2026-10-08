"""Excepciones propias del simulador de keytool.

Los módulos de lógica (keystore.py, crypto_utils.py) lanzan estas excepciones.
Solo mykeytool.py decide qué mensaje se muestra al usuario.
"""


class KeytoolError(Exception):
    """Base de todos los errores del simulador."""


class WrongPasswordError(KeytoolError):
    """Contraseña del almacén o del alias incorrecta."""


class AliasExistsError(KeytoolError):
    """Se intenta crear un alias que ya existe en el keystore."""


class AliasNotFoundError(KeytoolError):
    """El alias solicitado no existe en el keystore."""


class KeystoreNotFoundError(KeytoolError):
    """El archivo del almacén no existe."""


class KeystoreCorruptedError(KeytoolError):
    """El archivo del almacén existe pero no se puede leer (dañado)."""


class InvalidInputError(KeytoolError):
    """El usuario escribió algo no válido (contraseña corta, país mal escrito...)."""
