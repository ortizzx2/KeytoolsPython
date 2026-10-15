"""Persistencia del keystore simulado en keystore.json (Parte A).

Este módulo SOLO guarda y lee TEXTO. No hace criptografía de claves RSA
(eso es de crypto_utils.py, Parte B).

Estructura del archivo keystore.json:
{
  "keystore_password": "<iteraciones>$<sal>$<hash>   (nunca la contraseña en claro)",
  "keys": {
    "miAlias": {
      "private_key": "-----BEGIN ENCRYPTED PRIVATE KEY-----...",
      "public_key": "-----BEGIN PUBLIC KEY-----...",
      "dname": "CN=..., OU=..., O=..., L=..., ST=..., C=ES"
    }
  }
}

Dentro del programa, el almacén es un diccionario de Python con esa misma forma.
"""

import hashlib
import hmac
import json
import os

from errors import (
    AliasExistsError,
    AliasNotFoundError,
    InvalidInputError,
    KeystoreCorruptedError,
    KeystoreNotFoundError,
)

# Igual que el keytool de Java: la contraseña necesita al menos 6 caracteres.
MIN_PASSWORD_LENGTH = 6

# Cuántas veces se repite el hash. Más vueltas = más difícil adivinar contraseñas.
HASH_ITERATIONS = 200000


# ---------------------------------------------------------------------------
# Contraseña del almacén (hash con sal)
# ---------------------------------------------------------------------------

def _calculate_hash(password: str, salt_hex: str, iterations: int) -> str:
    """Convierte una contraseña en un hash (una huella) usando la sal.

    ¿Por qué no guardamos la contraseña tal cual?
    Porque quien abra keystore.json la vería. Con el hash solo ve un texto raro
    del que NO se puede recuperar la contraseña original.

    ¿Y la sal?
    Es un texto aleatorio distinto en cada almacén: dos almacenes con la misma
    contraseña tendrán hashes distintos.
    """
    # Paso 1: pasamos todo a bytes, que es lo que pide la función de hash.
    password_bytes = password.encode("utf-8")
    salt_bytes = bytes.fromhex(salt_hex)

    # Paso 2: PBKDF2 = repetir SHA-256 muchas veces mezclando contraseña y sal.
    hash_bytes = hashlib.pbkdf2_hmac("sha256", password_bytes, salt_bytes, iterations)

    # Paso 3: lo pasamos a texto hexadecimal para poder guardarlo en JSON.
    return hash_bytes.hex()


def check_password_length(password: str) -> None:
    """Lanza InvalidInputError si la contraseña tiene menos de 6 caracteres."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise InvalidInputError(
            "La contraseña debe tener al menos %d caracteres." % MIN_PASSWORD_LENGTH
        )


def verify_store_password(data: dict, password: str) -> bool:
    """Comprueba la contraseña del almacén contra el hash guardado.

    Devuelve True si es correcta y False si no.
    (Quien la llama decide qué hacer si es False: mykeytool.py lanza WrongPasswordError.)
    """
    # Paso 1: separamos el texto guardado "iteraciones$sal$hash" en sus 3 partes.
    iterations_text, salt_hex, saved_hash = data["keystore_password"].split("$")

    # Paso 2: calculamos el hash de lo que escribió el usuario, con la MISMA sal.
    new_hash = _calculate_hash(password, salt_hex, int(iterations_text))

    # Paso 3: comparamos. hmac.compare_digest funciona como ==, pero tarda
    # siempre lo mismo (evita ataques que miden el tiempo de respuesta).
    return hmac.compare_digest(new_hash, saved_hash)


# ---------------------------------------------------------------------------
# Crear, cargar y guardar el almacén
# ---------------------------------------------------------------------------

def exists(path: str) -> bool:
    """Devuelve True si el archivo del almacén existe."""
    return os.path.isfile(path)


def create(password: str) -> dict:
    """Crea un almacén NUEVO y VACÍO en memoria (todavía no se guarda en disco).

    Lanza InvalidInputError si la contraseña es demasiado corta.
    """
    check_password_length(password)

    # Paso 1: sal aleatoria de 16 bytes (os.urandom es seguro para esto).
    salt_hex = os.urandom(16).hex()

    # Paso 2: hash de la contraseña con esa sal.
    password_hash = _calculate_hash(password, salt_hex, HASH_ITERATIONS)

    # Paso 3: montamos el diccionario. Guardamos las 3 piezas en un solo texto.
    return {
        "keystore_password": "%d$%s$%s" % (HASH_ITERATIONS, salt_hex, password_hash),
        "keys": {},  # de momento no hay ningún alias
    }


def load(path: str) -> dict:
    """Lee el keystore del disco.

    Lanza KeystoreNotFoundError si no existe y KeystoreCorruptedError si el
    JSON no es válido o le faltan datos.
    """
    # Paso 1: ¿existe el archivo?
    if not exists(path):
        raise KeystoreNotFoundError("El almacén '%s' no existe." % path)

    # Paso 2: leemos el texto y lo convertimos de JSON a diccionario.
    try:
        with open(path, "r", encoding="utf-8") as file:
            data = json.load(file)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise KeystoreCorruptedError("El almacén '%s' está dañado (no es un JSON válido)." % path)

    # Paso 3: comprobamos que tiene la estructura esperada.
    _check_structure(data, path)
    return data


def _check_structure(data, path: str) -> None:
    """Revisa que el diccionario tenga todas las partes necesarias.

    Un JSON puede ser válido y aun así no ser un almacén nuestro
    (por ejemplo, si alguien borra a mano la parte "keys").
    """
    error_message = "El almacén '%s' está dañado (le faltan datos)." % path

    if not isinstance(data, dict):
        raise KeystoreCorruptedError(error_message)
    if "keystore_password" not in data or "keys" not in data:
        raise KeystoreCorruptedError(error_message)
    if not isinstance(data["keys"], dict):
        raise KeystoreCorruptedError(error_message)

    # El texto de la contraseña debe tener exactamente 3 partes: iteraciones$sal$hash.
    password_text = data["keystore_password"]
    if not isinstance(password_text, str) or len(password_text.split("$")) != 3:
        raise KeystoreCorruptedError(error_message)

    # Las iteraciones deben ser un número y la sal debe ser hexadecimal válido.
    iterations_text, salt_hex, _ = password_text.split("$")
    try:
        int(iterations_text)
        bytes.fromhex(salt_hex)
    except ValueError:
        raise KeystoreCorruptedError(error_message)

    # Cada alias debe tener sus tres textos, y el DN la forma "CN=..., C=..".
    for entry in data["keys"].values():
        if not isinstance(entry, dict):
            raise KeystoreCorruptedError(error_message)
        for field in ("private_key", "public_key", "dname"):
            if not isinstance(entry.get(field), str):
                raise KeystoreCorruptedError(error_message)
        for part in entry["dname"].split(", "):
            if "=" not in part:
                raise KeystoreCorruptedError(error_message)


def save(path: str, data: dict) -> None:
    """Escribe el keystore en disco como JSON.

    Truco de seguridad: primero escribimos en un archivo temporal y luego lo
    renombramos. Así, si el programa se cae a mitad de escribir, el almacén
    original NO se queda a medias ni se estropea.
    """
    temp_path = path + ".tmp"

    # Paso 1: escribimos todo en el archivo temporal.
    with open(temp_path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

    # Paso 2: reemplazamos el archivo real por el temporal.
    os.replace(temp_path, path)


# ---------------------------------------------------------------------------
# Alias (las claves guardadas)
# ---------------------------------------------------------------------------

def alias_exists(data: dict, alias: str) -> bool:
    """Indica si el alias ya está en el keystore."""
    return alias in data["keys"]


def check_alias_free(data: dict, alias: str) -> None:
    """Lanza AliasExistsError si el alias ya existe.

    Se usa ANTES de pedir los datos del titular, para no hacer perder
    tiempo al usuario si el alias ya está ocupado.
    """
    if alias_exists(data, alias):
        raise AliasExistsError(
            "No se ha generado el par de claves, el alias <%s> ya existe." % alias
        )


def add_entry(data: dict, alias: str, private_pem: str, public_pem: str, dname: str) -> None:
    """Añade una entrada al almacén en memoria (luego hay que llamar a save).

    Lanza AliasExistsError si el alias ya existe.
    """
    check_alias_free(data, alias)

    data["keys"][alias] = {
        "private_key": private_pem,
        "public_key": public_pem,
        "dname": dname,
    }


def get_entry(data: dict, alias: str) -> dict:
    """Devuelve la entrada del alias {private_key, public_key, dname}.

    Lanza AliasNotFoundError si no existe.
    """
    if not alias_exists(data, alias):
        raise AliasNotFoundError("El alias <%s> no existe en el almacén." % alias)
    return data["keys"][alias]
