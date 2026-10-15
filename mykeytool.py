"""
mykeytool.py  (Parte A)
-----------------------
Programa principal: simula el comando `keytool` de Java.

Uso:
    python3 mykeytool.py --help
    python3 mykeytool.py --genkeypair
    python3 mykeytool.py --certreq
    python3 mykeytool.py --exportcert

Este archivo SOLO se ocupa de hablar con el usuario (preguntar datos y mostrar
mensajes). El trabajo de verdad lo hacen otros módulos:
    - keystore.py      -> guardar / leer el almacén        (Parte A)
    - crypto_utils.py  -> claves RSA y CSR                  (Parte B)
    - errors.py        -> los errores propios del programa
"""

import argparse
import getpass
import sys

import crypto_utils
import keystore
from errors import InvalidInputError, KeytoolError, WrongPasswordError

# Nombre del archivo del almacén si el usuario no indica otro con --keystore.
DEFAULT_KEYSTORE = "keystore.json"

# Orden en el que se escriben las partes del DN (Distinguished Name).
DNAME_FIELDS = ["CN", "OU", "O", "L", "ST", "C"]


# ---------------------------------------------------------------------------
# Funciones para PREGUNTAR cosas al usuario
# ---------------------------------------------------------------------------

def ask_password(message):
    """Pide una contraseña SIN mostrarla en pantalla (getpass la oculta)."""
    return getpass.getpass(message)


def ask_text(message):
    """Pide un texto normal y le quita los espacios sobrantes de los extremos."""
    return input(message).strip()


def ask_alias():
    """Pide el alias y comprueba que no esté vacío."""
    alias = ask_text("Alias: ")
    if alias == "":
        raise InvalidInputError("El alias no puede estar vacío.")
    return alias


def ask_dname_field(message):
    """Pide una parte del DN (CN, OU, O, L o ST).

    No permitimos ',' ni '=' porque son los separadores del DN y romperían
    el texto guardado ("CN=Ana, OU=IT...").
    """
    value = ask_text(message)
    if "," in value or "=" in value:
        raise InvalidInputError("No se pueden usar los caracteres ',' ni '=' en este dato.")
    return value


def ask_country():
    """Pide el código de país y comprueba que sean exactamente 2 letras (ej. ES, US)."""
    country = ask_text("País, código de 2 letras (C) [ej. ES]: ")
    if len(country) != 2 or not country.isalpha():
        raise InvalidInputError("El país debe ser un código de 2 letras, por ejemplo ES.")
    return country.upper()


def ask_dname():
    """Pregunta los datos del titular (Distinguished Name, DN).

    Devuelve un diccionario, por ejemplo:
        {"CN": "Ana Perez", "OU": "IT", "O": "Empresa", "L": "Madrid", "ST": "Madrid", "C": "ES"}
    """
    print("Introduce los datos del titular:")
    dname = {}
    dname["CN"] = ask_dname_field("Nombre y apellidos (CN): ")
    dname["OU"] = ask_dname_field("Unidad organizativa (OU): ")
    dname["O"] = ask_dname_field("Organización (O): ")
    dname["L"] = ask_dname_field("Ciudad (L): ")
    dname["ST"] = ask_dname_field("Provincia/Estado (ST): ")
    dname["C"] = ask_country()

    if dname["CN"] == "":
        raise InvalidInputError("El nombre (CN) no puede estar vacío.")
    return dname


# ---------------------------------------------------------------------------
# Convertir el DN entre diccionario <-> texto
# (el almacén guarda el DN como texto; crypto_utils.build_csr lo pide como diccionario)
# ---------------------------------------------------------------------------

def dname_to_text(dname):
    """{"CN": "Ana", "C": "ES"} -> "CN=Ana, C=ES". Salta las partes vacías."""
    parts = []
    for field in DNAME_FIELDS:
        if dname.get(field, "") != "":
            parts.append(field + "=" + dname[field])
    return ", ".join(parts)


def text_to_dname(text):
    """"CN=Ana, C=ES" -> {"CN": "Ana", "C": "ES"} (la operación contraria)."""
    dname = {}
    for part in text.split(", "):
        field, value = part.split("=", 1)  # 1 = cortar solo en el primer '='
        dname[field] = value
    return dname


# ---------------------------------------------------------------------------
# Comando --genkeypair
# ---------------------------------------------------------------------------

def open_or_create_keystore(path):
    """Prepara el almacén para --genkeypair.

    - Si el archivo NO existe: pide una contraseña nueva (dos veces) y crea un almacén vacío.
    - Si el archivo YA existe: pide la contraseña y comprueba que es correcta.

    Devuelve el diccionario del almacén, listo para usar.
    """
    if keystore.exists(path):
        # Caso 1: el almacén ya existe -> cargarlo y verificar contraseña.
        data = keystore.load(path)
        password = ask_password("Contraseña del almacén: ")
        if not keystore.verify_store_password(data, password):
            raise WrongPasswordError("Contraseña del almacén incorrecta.")
        return data

    # Caso 2: el almacén no existe -> crearlo.
    print("El almacén '%s' no existe, se creará uno nuevo." % path)
    password = ask_password("Nueva contraseña del almacén: ")
    repeated = ask_password("Repite la contraseña: ")
    if password != repeated:
        raise InvalidInputError("Las contraseñas no coinciden.")
    return keystore.create(password)


def command_genkeypair(keystore_path):
    """Genera un par de claves RSA 2048 y lo guarda en el almacén."""

    # Paso 1: abrir (o crear) el almacén y comprobar la contraseña.
    data = open_or_create_keystore(keystore_path)

    # Paso 2: pedir el alias y comprobar que NO esté repetido.
    # Lo hacemos ya, antes de pedir más datos, para no hacer perder tiempo al usuario.
    alias = ask_alias()
    keystore.check_alias_free(data, alias)

    # Paso 3: pedir los datos del titular (DN).
    dname = ask_dname()

    # Paso 4: pedir la contraseña de la clave (la del alias).
    key_password = ask_password("Contraseña de la clave del alias: ")
    keystore.check_password_length(key_password)

    # Paso 5: generar las claves RSA (esto lo hace la Parte B).
    print("Generando par de claves RSA de 2048 bits...")
    key = crypto_utils.generate_keypair()

    # Paso 6: convertir a texto PEM. La privada se guarda CIFRADA con la
    # contraseña del alias, así nunca queda en claro dentro del archivo.
    private_pem = crypto_utils.private_key_to_pem(key, key_password)
    public_pem = crypto_utils.public_key_to_pem(key)

    # Paso 7: añadir al almacén y guardarlo en disco.
    keystore.add_entry(data, alias, private_pem, public_pem, dname_to_text(dname))
    keystore.save(keystore_path, data)

    print("Par de claves '%s' generado y guardado en '%s'." % (alias, keystore_path))


# ---------------------------------------------------------------------------
# Comando --certreq
# ---------------------------------------------------------------------------

def unlock_alias(keystore_path):
    """Pasos comunes de --certreq y --exportcert.

    Carga el almacén, comprueba su contraseña, busca el alias y descifra su
    clave privada. Devuelve (alias, entrada del almacén, clave privada).
    """

    # Paso 1: cargar el almacén. Si no existe o está dañado, salta un error.
    data = keystore.load(keystore_path)

    # Paso 2: pedir y comprobar la contraseña del almacén.
    store_password = ask_password("Contraseña del almacén: ")
    if not keystore.verify_store_password(data, store_password):
        raise WrongPasswordError("Contraseña del almacén incorrecta.")

    # Paso 3: pedir el alias y buscarlo (si no existe, salta AliasNotFoundError).
    alias = ask_alias()
    entry = keystore.get_entry(data, alias)

    # Paso 4: pedir la contraseña del alias y descifrar la clave privada.
    # Si la contraseña está mal, crypto_utils lanza WrongPasswordError.
    key_password = ask_password("Contraseña de la clave del alias: ")
    key = crypto_utils.private_key_from_pem(entry["private_key"], key_password)
    return alias, entry, key


def command_certreq(keystore_path):
    """Crea un archivo .csr (solicitud de certificado) a partir de un alias."""

    # Pasos 1-4: almacén, contraseña, alias y clave privada.
    alias, entry, key = unlock_alias(keystore_path)

    # Paso 5: construir el CSR en formato PEM (lo hace la Parte B).
    csr_pem = crypto_utils.build_csr(key, text_to_dname(entry["dname"]))

    # Paso 6: escribir el archivo <alias>.csr. Es binario (bytes), por eso "wb".
    file_name = alias + ".csr"
    with open(file_name, "wb") as file:
        file.write(csr_pem)

    print("Solicitud de certificado guardada en '%s'." % file_name)


# ---------------------------------------------------------------------------
# Comando --exportcert (ampliación)
# ---------------------------------------------------------------------------

def command_exportcert(keystore_path):
    """Crea un certificado autofirmado <alias>.crt y muestra su huella SHA-256."""

    # Pasos 1-4: almacén, contraseña, alias y clave privada.
    alias, entry, key = unlock_alias(keystore_path)

    # Paso 5: certificado autofirmado en PEM, válido 365 días (lo hace la Parte B).
    cert_pem = crypto_utils.build_self_signed_cert(key, text_to_dname(entry["dname"]))

    # Paso 6: escribir el archivo <alias>.crt.
    file_name = alias + ".crt"
    with open(file_name, "wb") as file:
        file.write(cert_pem)

    print("Certificado autofirmado guardado en '%s'." % file_name)
    print("Huella SHA-256: %s" % crypto_utils.certificate_fingerprint(cert_pem))


# ---------------------------------------------------------------------------
# Argumentos de la línea de comandos y programa principal
# ---------------------------------------------------------------------------

def create_parser():
    """Define qué opciones acepta el programa (--help, --genkeypair, --certreq...)."""
    parser = argparse.ArgumentParser(
        prog="mykeytool.py",
        description="Simulador en Python de la herramienta keytool de Java.",
        epilog=(
            "Ejemplos:\n"
            "  python3 mykeytool.py --genkeypair\n"
            "  python3 mykeytool.py --certreq\n"
            "  python3 mykeytool.py --exportcert\n"
            "  python3 mykeytool.py --genkeypair --keystore otro.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,  # respeta los saltos de línea del epilog
    )

    # Solo se puede elegir UNA de estas acciones a la vez.
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--genkeypair",
        "--genkey",  # nombre antiguo de keytool, también aceptado
        action="store_true",  # si aparece, vale True; si no, False
        help="Genera un par de claves RSA 2048 y lo guarda en el almacén (pide contraseña, alias y datos del titular).",
    )
    group.add_argument(
        "--certreq",
        action="store_true",
        help="Genera un archivo .csr (PEM) para un alias del almacén (pide contraseña del almacén y del alias).",
    )
    group.add_argument(
        "--exportcert",
        action="store_true",
        help="Genera un certificado autofirmado <alias>.crt (PEM) y muestra su huella SHA-256.",
    )

    parser.add_argument(
        "--keystore",
        default=DEFAULT_KEYSTORE,
        help="Archivo del almacén (por defecto: %s)." % DEFAULT_KEYSTORE,
    )
    return parser


def main():
    """Punto de entrada: lee los argumentos y ejecuta el comando elegido.

    Aquí está el ÚNICO try/except del programa. Todos los errores propios
    (KeytoolError) llegan hasta aquí y se muestran como un mensaje simple.
    """
    parser = create_parser()
    args = parser.parse_args()

    # Si no se eligió ningún comando, mostramos la ayuda.
    if not args.genkeypair and not args.certreq and not args.exportcert:
        parser.print_help()
        return 0

    try:
        if args.genkeypair:
            command_genkeypair(args.keystore)
        elif args.certreq:
            command_certreq(args.keystore)
        else:
            command_exportcert(args.keystore)
    except KeytoolError as error:
        # Error esperado (contraseña mal, alias repetido, almacén inexistente...).
        print("Error: %s" % error, file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        # El usuario pulsó Ctrl+C o Ctrl+D.
        print("\nOperación cancelada.", file=sys.stderr)
        return 1
    except OSError as error:
        # Problemas con archivos (sin permisos, disco lleno...).
        print("Error de archivo: %s" % error, file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
