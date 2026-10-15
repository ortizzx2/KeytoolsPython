# Matriz de pruebas: módulo criptográfico (`crypto_utils.py`)

Pruebas de la Parte B: generación de claves RSA, serialización PEM y creación
de la solicitud de certificado (CSR).

## Cómo ejecutarlas

```bash
python3 -m unittest discover tests -v
```

(En Windows: `py -m unittest discover tests -v`.) Resultado de la última
ejecución: **21 pruebas en total, todas correctas**: las 12 de este documento
y las 9 de la ampliación (ver `docs/ampliacion_certificado.md`).

Requisito: `cryptography` 42 o superior (los tests usan `not_valid_after_utc`).

## 1. Pruebas unitarias (`tests/test_crypto_utils.py`)

| ID | Función | Qué se comprueba | Resultado esperado | Estado |
|----|---------|------------------|--------------------|--------|
| C-01 | `generate_keypair` | Tamaño de la clave | 2048 bits | OK |
| C-02 | `public_key_to_pem` | Formato de la clave pública | Texto que empieza por `-----BEGIN PUBLIC KEY-----` | OK |
| C-03 | `private_key_to_pem` | La clave privada se guarda cifrada | Empieza por `-----BEGIN ENCRYPTED PRIVATE KEY-----` | OK |
| C-04 | `private_key_to_pem` + `private_key_from_pem` | Ida y vuelta con la contraseña correcta | La clave recuperada tiene la misma clave pública | OK |
| C-05 | `private_key_from_pem` | Contraseña incorrecta | Lanza `WrongPasswordError` | OK |
| C-06 | `build_csr` | Tipo y formato de salida | `bytes` que empiezan por `-----BEGIN CERTIFICATE REQUEST-----` | OK |
| C-07 | `build_csr` | El DN se incluye en la solicitud | CN y C coinciden con los datos de entrada | OK |
| C-08 | `build_csr` | Firma de la solicitud | La firma es válida | OK |
| C-09 | `build_csr` | Contenido del CSR | Contiene la clave pública y **nunca** la privada | OK |
| C-10 | `build_csr` | DN con campos vacíos o ausentes | Se omiten sin error | OK |
| C-11 | `build_csr` | DN completamente vacío | Lanza `ValueError` | OK |
| C-12 | `private_key_from_pem` | Clave guardada sin cifrar (almacén manipulado) | Lanza `KeystoreCorruptedError`, sin traza | OK |

## 2. Pruebas de integración con la CLI

Ejecutadas con el programa completo (`mykeytool.py`) y entradas simuladas del
usuario. Entradas comunes: alias `miAlias`, contraseña del almacén
`almacen123`, contraseña de la clave `clave1234`, CN `Ana Perez`, país `es`.

| ID | Comando | Escenario | Resultado esperado | Estado |
|----|---------|-----------|--------------------|--------|
| I-01 | `--genkeypair` | Almacén nuevo, datos válidos | Se crea el par de claves y se guarda en `keystore.json` | OK |
| I-02 | `--genkeypair` | Alias ya existente | Error controlado: el alias ya existe | OK |
| I-03 | `--certreq` | Contraseñas correctas | Se crea `miAlias.csr` | OK |
| I-04 | `--certreq` | Contraseña de la clave del alias incorrecta | Error controlado: "Contraseña de la clave incorrecta." | OK |
| I-05 | `--certreq` | Contraseña del almacén incorrecta | Error controlado: "Contraseña del almacén incorrecta." | OK |
| I-06 | `--genkeypair` | Contenido de `keystore.json` | No aparece `BEGIN PRIVATE KEY`; sí `BEGIN ENCRYPTED PRIVATE KEY` | OK |

## 3. Verificación externa del CSR con OpenSSL

```bash
openssl req -in miAlias.csr -noout -verify -subject
```

Resultado:

```
Certificate request self-signature verify OK
subject=CN=Ana Perez, OU=IT, O=Empresa, L=Madrid, ST=Madrid, C=ES
```

Esto confirma que el CSR generado es válido según una herramienta ajena a
nuestro código.
