# Ampliación: certificado autofirmado y huella digital

Funciones añadidas a `crypto_utils.py` (Parte B):

| Función | Qué hace |
|---------|----------|
| `build_self_signed_cert(key, dname, days=365)` | Crea un certificado X.509 autofirmado en PEM. El titular y el emisor son el mismo y se firma con la propia clave privada. |
| `certificate_fingerprint(cert_pem)` | Devuelve la huella SHA-256 del certificado (`AA:BB:...`), como la muestra `keytool -list`. |

Es lo que hace `keytool -genkeypair` junto al par de claves, y la base de
`keytool -export` (exportar el certificado a un `.crt`).

## Pruebas (`tests/test_crypto_utils.py`, clase `PruebasCertificadoAutofirmado`)

| ID | Qué se comprueba | Resultado esperado | Estado |
|----|------------------|--------------------|--------|
| A-01 | Formato de salida | `bytes` que empiezan por `-----BEGIN CERTIFICATE-----` | OK |
| A-02 | Titular y emisor | Son iguales y contienen el CN indicado | OK |
| A-03 | Firma | Válida con su propia clave pública | OK |
| A-04 | Clave pública incluida | Coincide con la del par generado | OK |
| A-05 | Validez | Dura exactamente los días pedidos | OK |
| A-06 | `days=0` | Lanza `ValueError` | OK |
| A-07 | DN vacío | Lanza `ValueError` | OK |
| A-08 | Formato de la huella | 32 pares hexadecimales en mayúsculas separados por `:` (95 caracteres) | OK |
| A-09 | Valor de la huella | Igual al SHA-256 del certificado en DER | OK |

## Verificación externa con OpenSSL

```bash
openssl x509 -in certificado.crt -noout -subject -issuer -dates -fingerprint -sha256
```

El titular y el emisor coinciden, las fechas son correctas y la huella de
OpenSSL es idéntica a la que devuelve `certificate_fingerprint`.

## Pendiente de integrar en la CLI

Falta añadir una opción (por ejemplo `--exportcert`) en `mykeytool.py` que
use estas funciones. Es un cambio en el archivo de la Parte A, a coordinar con
el otro integrante.
