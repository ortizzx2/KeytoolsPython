# KeytoolsPython — Simulador de Java Keytool en Python

Aplicación de línea de comandos (CLI) que simula las funciones básicas de la herramienta `keytool` de Java.

## Integrantes

- Persona A: _(nombre completo)_ — CLI, persistencia del almacén, errores de almacén/alias
- Persona B: _(nombre completo)_ — criptografía (RSA, DN, CSR)

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
| `crypto_utils.py` | Genera claves RSA 2048, el DN y el CSR |
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

_(Persona B: RSA 2048, cifrado de la clave privada, formato CSR/PEM)_

## Pruebas

Pruebas automáticas del almacén:

```
python3 -m unittest discover tests -v
```

### Matriz de pruebas

_(Ambos: completar con las pruebas manuales ejecutadas)_

| # | Prueba | Resultado esperado | Resultado |
|---|---|---|---|
| 1 | `--help` | Lista comandos | |
| 2 | `--genkeypair` con almacén nuevo | Crea `keystore.json` | |
| 3 | `--genkeypair` con alias repetido | Error "el alias ya existe" | |
| 4 | Contraseña del almacén incorrecta | Error y rechazo | |
| 5 | Almacén inexistente / dañado | Mensaje claro | |
| 6 | `--certreq` correcto | Crea `<alias>.csr` | |
| 7 | `--certreq` con contraseña de alias incorrecta | Error | |
