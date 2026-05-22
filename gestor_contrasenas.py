"""
Gestor de Contraseñas CLI (Educativo)
=====================================

Guarda y cifra contraseñas localmente usando criptografía simétrica
estándar (Fernet = AES-128-CBC + HMAC-SHA256).

¿Cómo se protege la información?
--------------------------------
1. El usuario introduce una CONTRASEÑA MAESTRA.
2. Se deriva una CLAVE de cifrado a partir de esa contraseña usando
   PBKDF2-HMAC-SHA256 con 480.000 iteraciones y un "salt" aleatorio.
3. Las contraseñas guardadas se cifran con esa clave antes de
   escribirse a disco. Sin la contraseña maestra no se pueden
   descifrar.

Dependencias:
    pip install cryptography

Uso:
    python gestor_contrasenas.py
"""

import base64
import getpass
import json
import os
import secrets
import string
import sys
from pathlib import Path

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    print("[!] Falta la librería 'cryptography'. Instálala con:")
    print("    pip install cryptography")
    sys.exit(1)


# Archivo donde se guarda la "bóveda" cifrada.
RUTA_BOVEDA = Path(__file__).parent / "boveda.json"

# Iteraciones recomendadas por OWASP (2023+) para PBKDF2-SHA256.
ITERACIONES = 480_000


# ---------------------------------------------------------------------------
# Criptografía
# ---------------------------------------------------------------------------

def derivar_clave(contrasena_maestra: str, salt: bytes) -> bytes:
    """
    Deriva una clave Fernet (32 bytes en base64) a partir de la
    contraseña maestra y un salt.

    PBKDF2 hace lento el cálculo a propósito (480k iteraciones)
    para dificultar ataques de fuerza bruta sobre el archivo.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERACIONES,
    )
    clave_bruta = kdf.derive(contrasena_maestra.encode("utf-8"))
    return base64.urlsafe_b64encode(clave_bruta)


def cifrar(fernet: Fernet, texto: str) -> str:
    return fernet.encrypt(texto.encode("utf-8")).decode("utf-8")


def descifrar(fernet: Fernet, token: str) -> str:
    return fernet.decrypt(token.encode("utf-8")).decode("utf-8")


# ---------------------------------------------------------------------------
# Persistencia de la bóveda
# ---------------------------------------------------------------------------

def cargar_boveda():
    """Devuelve el diccionario de la bóveda o None si no existe."""
    if not RUTA_BOVEDA.exists():
        return None
    with open(RUTA_BOVEDA, "r", encoding="utf-8") as f:
        return json.load(f)


def guardar_boveda(boveda: dict):
    with open(RUTA_BOVEDA, "w", encoding="utf-8") as f:
        json.dump(boveda, f, indent=2)


def crear_boveda(contrasena_maestra: str) -> dict:
    """Crea una bóveda vacía con un salt aleatorio nuevo."""
    salt = secrets.token_bytes(16)
    fernet = Fernet(derivar_clave(contrasena_maestra, salt))

    # Guardamos un "verificador" cifrado: una cadena conocida.
    # Al abrir la bóveda intentaremos descifrarla para comprobar
    # que la contraseña maestra es correcta SIN guardar la contraseña.
    verificador = cifrar(fernet, "boveda-ok")

    return {
        "salt": base64.b64encode(salt).decode("ascii"),
        "verificador": verificador,
        "entradas": {},  # nombre_servicio -> {usuario, contrasena_cifrada}
    }


# ---------------------------------------------------------------------------
# Generador de contraseñas
# ---------------------------------------------------------------------------

def generar_contrasena(longitud: int = 16, simbolos: bool = True) -> str:
    """
    Genera una contraseña aleatoria fuerte usando `secrets`
    (criptográficamente seguro, a diferencia de `random`).
    """
    alfabeto = string.ascii_letters + string.digits
    if simbolos:
        alfabeto += "!@#$%^&*()-_=+[]{},.?"
    return "".join(secrets.choice(alfabeto) for _ in range(longitud))


# ---------------------------------------------------------------------------
# Funciones del menú
# ---------------------------------------------------------------------------

def añadir_entrada(boveda: dict, fernet: Fernet):
    servicio = input("Servicio (ej. github): ").strip()
    if not servicio:
        print("[!] El nombre del servicio no puede estar vacío.")
        return
    if servicio in boveda["entradas"]:
        if input(f"'{servicio}' ya existe. ¿Sobrescribir? (s/N): ").lower() != "s":
            return

    usuario = input("Usuario o email: ").strip()

    opcion = input("¿Generar contraseña automáticamente? (S/n): ").strip().lower()
    if opcion in ("", "s", "si", "sí"):
        try:
            longitud = int(input("Longitud [16]: ") or 16)
        except ValueError:
            longitud = 16
        contrasena = generar_contrasena(longitud)
        print(f"[+] Contraseña generada: {contrasena}")
    else:
        contrasena = getpass.getpass("Contraseña: ")

    boveda["entradas"][servicio] = {
        "usuario": usuario,
        "contrasena": cifrar(fernet, contrasena),
    }
    guardar_boveda(boveda)
    print(f"[✓] Entrada '{servicio}' guardada y cifrada.")


def listar_entradas(boveda: dict):
    if not boveda["entradas"]:
        print("[i] La bóveda está vacía.")
        return
    print("\nServicios guardados:")
    for nombre in sorted(boveda["entradas"]):
        usuario = boveda["entradas"][nombre]["usuario"]
        print(f"  - {nombre}  ({usuario})")


def consultar_entrada(boveda: dict, fernet: Fernet):
    servicio = input("Servicio a consultar: ").strip()
    entrada = boveda["entradas"].get(servicio)
    if not entrada:
        print(f"[!] No existe ninguna entrada para '{servicio}'.")
        return
    try:
        clara = descifrar(fernet, entrada["contrasena"])
    except InvalidToken:
        print("[!] No se pudo descifrar (¿bóveda corrupta?).")
        return
    print(f"\n  Servicio   : {servicio}")
    print(f"  Usuario    : {entrada['usuario']}")
    print(f"  Contraseña : {clara}\n")


def eliminar_entrada(boveda: dict):
    servicio = input("Servicio a eliminar: ").strip()
    if servicio not in boveda["entradas"]:
        print(f"[!] No existe '{servicio}'.")
        return
    if input(f"¿Eliminar '{servicio}'? (s/N): ").lower() != "s":
        return
    del boveda["entradas"][servicio]
    guardar_boveda(boveda)
    print(f"[✓] '{servicio}' eliminada.")


def generar_suelta():
    """Genera una contraseña sin guardarla."""
    try:
        longitud = int(input("Longitud [16]: ") or 16)
    except ValueError:
        longitud = 16
    simbolos = input("¿Incluir símbolos? (S/n): ").strip().lower() not in ("n", "no")
    print(f"\n  -> {generar_contrasena(longitud, simbolos)}\n")


# ---------------------------------------------------------------------------
# Flujo principal
# ---------------------------------------------------------------------------

def abrir_o_crear_boveda():
    """
    Devuelve (boveda, fernet) listos para usar.
    Si la bóveda no existe, la crea pidiendo contraseña maestra dos veces.
    Si existe, pide la contraseña maestra y la valida.
    """
    boveda = cargar_boveda()

    if boveda is None:
        print("[i] No se encontró una bóveda. Vamos a crear una nueva.\n")
        while True:
            maestra = getpass.getpass("Crea tu contraseña MAESTRA: ")
            if len(maestra) < 8:
                print("[!] Usa al menos 8 caracteres.")
                continue
            confirm = getpass.getpass("Repite la contraseña maestra: ")
            if maestra != confirm:
                print("[!] No coinciden, vuelve a intentarlo.\n")
                continue
            break
        boveda = crear_boveda(maestra)
        guardar_boveda(boveda)
        salt = base64.b64decode(boveda["salt"])
        fernet = Fernet(derivar_clave(maestra, salt))
        print("[✓] Bóveda creada.\n")
        return boveda, fernet

    # La bóveda ya existe -> validar contraseña maestra.
    salt = base64.b64decode(boveda["salt"])
    for intento in range(3):
        maestra = getpass.getpass("Contraseña maestra: ")
        fernet = Fernet(derivar_clave(maestra, salt))
        try:
            if descifrar(fernet, boveda["verificador"]) == "boveda-ok":
                print("[✓] Bóveda desbloqueada.\n")
                return boveda, fernet
        except InvalidToken:
            pass
        print(f"[!] Contraseña incorrecta ({2 - intento} intentos restantes).")

    print("[!] Demasiados intentos fallidos. Saliendo.")
    sys.exit(1)


def menu():
    print("""
╔══════════════════════════════════════════╗
║   GESTOR DE CONTRASEÑAS CLI (EDUCATIVO)  ║
╚══════════════════════════════════════════╝
  1. Añadir / actualizar entrada
  2. Listar servicios guardados
  3. Consultar contraseña
  4. Eliminar entrada
  5. Generar contraseña (sin guardar)
  0. Salir
""")
    return input("Opción: ").strip()


def main():
    print("=" * 50)
    print("  Gestor de Contraseñas CLI — uso educativo")
    print("=" * 50)
    print(f"  Bóveda en: {RUTA_BOVEDA}\n")

    boveda, fernet = abrir_o_crear_boveda()

    acciones = {
        "1": lambda: añadir_entrada(boveda, fernet),
        "2": lambda: listar_entradas(boveda),
        "3": lambda: consultar_entrada(boveda, fernet),
        "4": lambda: eliminar_entrada(boveda),
        "5": generar_suelta,
    }

    while True:
        opcion = menu()
        if opcion == "0":
            print("¡Hasta luego!")
            break
        accion = acciones.get(opcion)
        if accion:
            accion()
        else:
            print("[!] Opción no válida.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrumpido por el usuario.")
