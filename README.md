# WAPA gh0stl1nk

Un *covert channel* para envío de mensajes y tranferencia de ficheros construida sobre el protocolo 802.11 usando **Scapy** y **AES-CBC**. Permite enviar mensajes cifrados y fragmentar/ensamblar archivos de forma transparente, con confirmaciones de recepción (ACKs) automáticas y detección de duplicados.

---

## Características

- **Mensajería cifrada** con AES-CBC y padding PKCS#7
- **Confirmaciones de recepción (ACKs)** para asegurar la entrega de mensajes
- **Retransmisión automática** hasta recibir el ACK (configurable)
- **Fragmentación y reensamblado de archivos** grandes, con sesiones identificadas
- **Detección de mensajes duplicados** para evitar procesar el mismo paquete varias veces
- **Interfaz interactiva** en línea de comandos

---

## Requisitos

- Python 3.7+
- [Scapy](https://scapy.net/)
- [PyCryptodome](https://pycryptodome.readthedocs.io/)

```bash
pip install scapy pycryptodome
```

---

## Instalación

1. Clona este repositorio:
   ```bash
   git clone https://github.com/tu_usuario/wapa_ghostlink.git
   cd wapa_ghostlink
   ```
2. Instala las dependencias con `pip` (ver sección **Requisitos** arriba):
   ```bash
   pip install -r requirements.txt
   ```

---

## Configuración

Al ejecutar el script, se solicitarán los siguientes parámetros:

1. **Interfaz de red** (`mon1`, `wlan0mon`, etc.)
2. **Nombre de usuario** (identificador en los mensajes)
3. **Nombre de la “sala”** (PSK o clave compartida)

Estos valores también están definidos al inicio del código como variables por defecto:

```python
iface      = "mon1"               # Interfaz por defecto
username   = "d0t"                # Usuario por defecto
cipher_key = b"mysharedsecret00"  # Clave AES de 16 bytes
count      = 5                    # Retransmisiones por mensaje
maxpayload = 1024                 # Tamaño máximo de datos por paquete
verbose    = False                # Modo detallado
```

> **Nota**: La clave de sala se ajusta con padding a 16 bytes mediante `adjust_psk()`.

---

## Uso

1. **Iniciar la herramienta**:
   ```bash
   python ghostlink.py
   ```
2. **Responder a los prompts**:
   ```
   [>] Select the interface to use: mon1
   [>] Enter your username: d0t
   [>] Enter the room name: secretr00m
   ```
3. **Enviar mensajes**:
   - Escribe texto y presiona **Enter**.
   - `quit` o `exit` para salir.

4. **Enviar archivos**:
   - Usa la sintaxis: `!{/ruta/al/archivo}`
   - Ejemplo:
     ```
     mensaje> !{/home/user/documento.pdf}
     ```
   - El archivo se fragmentará automáticamente y se enviarán todos los fragmentos.

5. **Recepción**:
   - Los mensajes y fragmentos de archivo entrantes se descifran, procesan y muestran en pantalla.
   - Cuando todos los fragmentos de una sesión llegan, el archivo se ensambla y guarda como:
     ```
     ghostlink_recv_<SESSION_ID>.bin
     ```

---

## Estructura del Proyecto

```
.
├── ghostlink.py      # Script principal
├── protocol.py       # Funciones de fragmentación y desfragmentación
├── LICENSE           # Licencia MIT
└── README.md         # Documentación
```

---

## Contribuir

1. Haz un fork del repositorio.
2. Crea una rama con tu feature/fix:
   ```bash
   git checkout -b feature-nombre
   ```
3. Realiza los cambios y pruebas necesarios.
4. Abre un Pull Request describiendo tus mejoras.

---

## Licencia

Este proyecto se distribuye bajo la [Licencia GPLv3.0](LICENSE).
