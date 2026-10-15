# KeytoolsPython — Simulador de Java Keytool en Python

Aplicación de línea de comandos (CLI) que simula las funciones básicas de la herramienta `keytool` de Java.

## Integrantes

- Persona A: Isaac Trujillo Bombín — CLI, persistencia del almacén, errores de almacén/alias
- Persona B: Edgar Ortiz Méndez — criptografía (RSA, DN, CSR)

## Instalación

Necesitas Python 3 y la librería `cryptography`:

```
pip install cryptography
```

## Estructura del proyecto

| Archivo | Para qué sirve |
|---|---|
| `mykeytool.py` | Programa principal: lee los comandos y habla con el usuario |
| `keystore.py` | Guarda y lee el almacén `keystore.json` (contraseña con hash + sal) |
| `crypto_utils.py` | Genera claves RSA 2048, el DN, el CSR y el certificado autofirmado |
| `docs/` | Matriz de pruebas criptográficas y documentación de la ampliación |
| `errors.py` | Errores propios del programa |
| `tests/` | Pruebas |

## Guía de uso

### Ver la ayuda

```
python3 mykeytool.py --help
```

### Crear un par de claves (`--genkeypair`)

Si `keystore.json` no existe, se crea. Si existe, pide su contraseña.

```
$ python3 mykeytool.py --genkeypair
El almacén 'keystore.json' no existe, se creará uno nuevo.
Nueva contraseña del almacén:
Repite la contraseña:
Alias: ana
Introduce los datos del titular:
Nombre y apellidos (CN): Ana Perez
Unidad organizativa (OU): IT
Organización (O): MiEmpresa
Ciudad (L): Madrid
Provincia/Estado (ST): Madrid
País, código de 2 letras (C) [ej. ES]: ES
Contraseña de la clave del alias:
Generando par de claves RSA de 2048 bits...
Par de claves 'ana' generado y guardado en 'keystore.json'.
```

Las contraseñas no se ven al escribirlas. Mínimo 6 caracteres (como en keytool).

### Generar una solicitud de certificado (`--certreq`)

```
$ python3 mykeytool.py --certreq
Contraseña del almacén:
Alias: ana
Contraseña de la clave del alias:
Solicitud de certificado guardada en 'ana.csr'.
```

### Exportar un certificado autofirmado (`--exportcert`, ampliación)

```
$ python3 mykeytool.py --exportcert
Contraseña del almacén:
Alias: ana
Contraseña de la clave del alias:
Certificado autofirmado guardado en 'ana.crt'.
Huella SHA-256: 68:D7:8D:46:42:8E:FB:A4:...:44:06:11
```

Más detalles en [`docs/ampliacion_certificado.md`](docs/ampliacion_certificado.md).

`--genkey` también se acepta como nombre alternativo de `--genkeypair`.

### Usar otro archivo de almacén

```
python3 mykeytool.py --genkeypair --keystore otro.json
```

### Errores controlados

Ningún error enseña trazas de Python; se muestra un mensaje y el programa termina con código 1.

```
Error: Contraseña del almacén incorrecta.
Error: No se ha generado el par de claves, el alias <ana> ya existe.
Error: El almacén 'keystore.json' no existe.
Error: El almacén 'keystore.json' está dañado (no es un JSON válido).
```

## Cómo se guarda el almacén

`keystore.json` guarda la contraseña del almacén como **hash PBKDF2-SHA256 con sal** (nunca en claro) y, por cada alias, la clave privada (cifrada), la pública y el DN.

## Explicación criptográfica

- **RSA 2048:** cada alias tiene un par de claves RSA de 2048 bits con exponente público 65537. La pública se puede compartir; la privada solo la tiene el titular y sirve para firmar.
- **Clave privada cifrada:** se guarda en PKCS#8 (`BEGIN ENCRYPTED PRIVATE KEY`), cifrada con la contraseña del alias. Sin esa contraseña no se puede usar, aunque alguien copie `keystore.json`.
- **CSR (PKCS#10):** contiene la clave pública y el DN, firmado con SHA-256 y la clave privada para demostrar que el solicitante la posee. La clave privada nunca va dentro.
- **PEM:** los datos binarios (DER) codificados en Base64 entre líneas `-----BEGIN ...-----` / `-----END ...-----`, para poder guardarlos como texto.
- **Certificado autofirmado (ampliación):** certificado X.509 donde emisor y titular son el mismo, firmado con la propia clave; se identifica por su huella SHA-256.

Detalle de las pruebas criptográficas en [`docs/pruebas_crypto.md`](docs/pruebas_crypto.md).

## Pruebas

Pruebas automáticas (almacén y criptografía, 31 en total):

```
python3 -m unittest discover tests -v
```

### Matriz de pruebas

Pruebas manuales ejecutadas con el programa completo:

| # | Prueba | Resultado esperado | Resultado |
|---|---|---|---|
| 1 | `--help` | Lista comandos | OK |
| 2 | `--genkeypair` con almacén nuevo | Crea `keystore.json` | OK |
| 3 | `--genkeypair` con alias repetido | Error "el alias ya existe" | OK |
| 4 | Contraseña del almacén incorrecta | Error y rechazo | OK |
| 5 | Almacén inexistente / dañado | Mensaje claro | OK |
| 6 | `--certreq` correcto | Crea `<alias>.csr` | OK |
| 7 | `--certreq` con contraseña de alias incorrecta | Error | OK |
| 8 | `--certreq` con alias inexistente | Error "el alias no existe" | OK |
| 9 | Validar `ana.csr` con `openssl req -verify` | Firma correcta | OK |
| 10 | `--genkey` (nombre alternativo) | Igual que `--genkeypair` | OK |
| 11 | `--exportcert` correcto | Crea `<alias>.crt` y muestra la huella | OK |
| 12 | Huella de `--exportcert` frente a `openssl x509 -fingerprint -sha256` | Coinciden | OK |
| 13 | Entrada de alias dañada a mano en `keystore.json` | Error "almacén dañado", sin traza | OK |
| 14 | Datos no válidos (coma en el DN, CN vacío, contraseña < 6) | Error claro | OK |
| 15 | Dos comandos a la vez (`--certreq --exportcert`) | argparse lo rechaza | OK |
