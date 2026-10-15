"""
Pruebas del módulo keystore.py (Parte A).

Cómo ejecutarlas (desde la carpeta del proyecto):
    python3 -m unittest discover tests -v
"""

import os
import sys
import tempfile
import unittest

# Permite importar keystore.py y errors.py, que están en la carpeta de arriba.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import keystore
from errors import (
    AliasExistsError,
    AliasNotFoundError,
    InvalidInputError,
    KeystoreCorruptedError,
    KeystoreNotFoundError,
)


class PruebasKeystore(unittest.TestCase):

    def setUp(self):
        # Antes de cada prueba: carpeta temporal para no ensuciar el proyecto.
        self.folder = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.folder.name, "keystore.json")

    def tearDown(self):
        self.folder.cleanup()

    def test_crear_guardar_y_cargar(self):
        data = keystore.create("secreto123")
        keystore.save(self.path, data)
        self.assertEqual(data, keystore.load(self.path))

    def test_password_correcta(self):
        data = keystore.create("secreto123")
        self.assertTrue(keystore.verify_store_password(data, "secreto123"))

    def test_password_incorrecta(self):
        data = keystore.create("secreto123")
        self.assertFalse(keystore.verify_store_password(data, "otraCosa"))

    def test_password_demasiado_corta(self):
        with self.assertRaises(InvalidInputError):
            keystore.create("abc")

    def test_alias_duplicado(self):
        data = keystore.create("secreto123")
        keystore.add_entry(data, "ana", "priv", "pub", "CN=Ana")
        with self.assertRaises(AliasExistsError):
            keystore.add_entry(data, "ana", "priv2", "pub2", "CN=Ana2")

    def test_alias_inexistente(self):
        data = keystore.create("secreto123")
        with self.assertRaises(AliasNotFoundError):
            keystore.get_entry(data, "noexiste")

    def test_almacen_inexistente(self):
        with self.assertRaises(KeystoreNotFoundError):
            keystore.load(self.path)

    def test_almacen_con_json_roto(self):
        with open(self.path, "w") as file:
            file.write("{ esto no es json")
        with self.assertRaises(KeystoreCorruptedError):
            keystore.load(self.path)

    def test_almacen_sin_estructura(self):
        with open(self.path, "w") as file:
            file.write('{"hola": 1}')
        with self.assertRaises(KeystoreCorruptedError):
            keystore.load(self.path)


if __name__ == "__main__":
    unittest.main()
