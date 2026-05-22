# 🔐 Gestor de Contraseñas CLI

Un gestor de contraseñas de línea de comandos escrito en **Python**, que
guarda y **cifra localmente** tus credenciales con criptografía estándar
(AES-128-CBC + HMAC-SHA256 vía **Fernet**) y deriva la clave con
**PBKDF2-HMAC-SHA256** (480.000 iteraciones, recomendación OWASP).

> ⚠️ **Aviso**: este proyecto es **educativo**. Aunque utiliza primitivas
> criptográficas sólidas, no ha pasado una auditoría profesional. Para
> uso real prefiere gestores consolidados como **Bitwarden**, **KeePassXC**
> o **1Password**.

---

## 📋 Tabla de contenidos

- [Características](#-características)
- [Cómo te protege](#-cómo-te-protege)
- [Requisitos](#-requisitos)
- [Instalación](#-instalación)
- [Uso](#-uso)
- [Ejemplo de ejecución](#-ejemplo-de-ejecución)
- [Estructura de la bóveda](#-estructura-de-la-bóveda)
- [Modelo de amenaza](#-modelo-de-amenaza)
- [Buenas prácticas](#-buenas-prácticas)
- [Limitaciones](#-limitaciones)
- [Próximas mejoras](#-próximas-mejoras)
- [Licencia](#-licencia)

---

## ✨ Características

- 🔒 Cifrado **simétrico autenticado** con Fernet (AES-128-CBC + HMAC).
- 🧂 **Salt aleatorio** único por bóveda (16 bytes).
- 🐌 Derivación de clave **PBKDF2-HMAC-SHA256** con 480.000 iteraciones.
- 🎲 Generador de contraseñas con `secrets` (criptográficamente seguro).
- 🙈 Entrada de contraseñas oculta con `getpass`.
- ✅ Validación de la contraseña maestra mediante un **verificador cifrado**
  (la contraseña nunca se guarda).
- 📁 Bóveda en un único archivo `boveda.json` portable.
- 📚 Código comentado pensado para **aprender** criptografía aplicada.

---

## 🛡️ Cómo te protege

| Componente | Para qué sirve |
|---|---|
| Contraseña maestra | No se guarda; sólo se usa para derivar la clave en memoria. |
| PBKDF2 (480.000 it.) | Hace lento el cálculo a propósito → frena fuerza bruta. |
| Salt aleatorio | Impide ataques con tablas arcoíris / claves precomputadas. |
| Fernet (AES + HMAC) | Cifrado **autenticado**: detecta si el archivo fue manipulado. |
| `secrets.choice` | Generación de contraseñas con entropía criptográfica real. |
| Verificador cifrado | Valida la maestra sin almacenarla en claro. |

> 💡 Si pierdes la contraseña maestra, **no hay recuperación posible**.
> Eso es exactamente lo que demuestra que el cifrado está bien hecho.

---

## 📦 Requisitos

- Python **3.8** o superior.
- Librería [`cryptography`](https://cryptography.io/):

```bash
pip install cryptography
```

---

## 🚀 Instalación

```bash
git clone https://github.com/<tu-usuario>/gestor-contrasenas-cli.git
cd gestor-contrasenas-cli
pip install cryptography
```

---

## ▶️ Uso

```bash
python gestor_contrasenas.py
```

- La **primera vez** se te pedirá crear la contraseña maestra.
- Las siguientes ejecuciones la pedirán para desbloquear la bóveda.
- Tras **3 intentos fallidos** el programa se cierra.

### Menú principal

```
1. Añadir / actualizar entrada
2. Listar servicios guardados
3. Consultar contraseña
4. Eliminar entrada
5. Generar contraseña (sin guardar)
0. Salir
```

---

## 🖥️ Ejemplo de ejecución

```
==================================================
  Gestor de Contraseñas CLI — uso educativo
==================================================
  Bóveda en: .../boveda.json

[i] No se encontró una bóveda. Vamos a crear una nueva.

Crea tu contraseña MAESTRA: ********
Repite la contraseña maestra: ********
[✓] Bóveda creada.

╔══════════════════════════════════════════╗
║   GESTOR DE CONTRASEÑAS CLI (EDUCATIVO)  ║
╚══════════════════════════════════════════╝
  1. Añadir / actualizar entrada
  ...

Opción: 1
Servicio (ej. github): github
Usuario o email: jossg@example.com
¿Generar contraseña automáticamente? (S/n): s
Longitud [16]: 20
[+] Contraseña generada: a8#K2pLm9!nQ4xR7v$Bz
[✓] Entrada 'github' guardada y cifrada.
```

---

## 🗂️ Estructura de la bóveda

El archivo `boveda.json` tiene este aspecto (todo lo sensible está cifrado):

```json
{
  "salt": "Zm9vYmFyYmF6cXV4MTIzNA==",
  "verificador": "gAAAAABl...==",
  "entradas": {
    "github": {
      "usuario": "jossg@example.com",
      "contrasena": "gAAAAABl...=="
    }
  }
}
```

- `salt` — público; se necesita junto con la maestra para derivar la clave.
- `verificador` — texto conocido cifrado, sirve para validar la maestra.
- `entradas[*].contrasena` — token Fernet (autenticado).

---

## 🎯 Modelo de amenaza

**Protege contra:**

- 👀 Alguien que copia tu archivo `boveda.json` y no conoce la maestra.
- 🧮 Ataques de fuerza bruta acelerados (gracias a PBKDF2 + salt).
- ✏️ Manipulación del archivo (el HMAC lo detecta al descifrar).

**NO protege contra:**

- 🦠 Malware o keyloggers en tu equipo que vean la maestra al escribirla.
- 🕵️ Volcado de memoria mientras la bóveda está desbloqueada.
- 🤫 Que escribas la maestra en un Post-it pegado al monitor.
- 👤 Adversarios con acceso físico mientras la sesión está abierta.

---

## ✅ Buenas prácticas

- Usa una contraseña maestra **larga** (≥ 14 caracteres) y única.
- Haz **copias de seguridad** del archivo `boveda.json` en un sitio seguro.
- **Nunca subas** `boveda.json` a un repositorio público
  (añádelo a `.gitignore`).
- No reutilices contraseñas — deja que el generador haga su trabajo.

Ejemplo de `.gitignore`:

```gitignore
boveda.json
__pycache__/
*.pyc
```

---

## ⚠️ Limitaciones

Este proyecto es didáctico. Comparado con un gestor profesional, **no**
implementa:

- Sincronización en la nube ni multi-dispositivo.
- Bloqueo automático por inactividad.
- Autocompletado en el navegador.
- Compartir entradas con otros usuarios.
- 2FA / claves hardware (YubiKey, etc.).
- Auditoría de contraseñas filtradas (Have I Been Pwned).

---

## 🛠️ Próximas mejoras

- [ ] Argumentos por línea de comandos (`argparse`) para usar sin menú.
- [ ] Exportar / importar bóveda (en formato cifrado).
- [ ] Búsqueda parcial por servicio.
- [ ] Cambio de contraseña maestra (re-cifrado completo).
- [ ] Indicador de fortaleza de contraseña.
- [ ] Bloqueo automático tras N minutos de inactividad.
- [ ] Integración opcional con la API de **Have I Been Pwned**.

---

## 📄 Licencia

Distribuido bajo licencia **MIT**. Consulta el archivo `LICENSE` para más
información.

---

## 🙋 Autor

Hecho con ❤️ con fines educativos.
**El conocimiento de criptografía implica responsabilidad — y humildad:
no inventes tu propio cifrado para uso real.**
