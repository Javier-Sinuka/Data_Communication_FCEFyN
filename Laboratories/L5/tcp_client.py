#!/usr/bin/env python3
"""
Cliente TCP mínimo - TP5 Redes de Computadoras.

Uso:
    python tcp_client.py                          # se conecta a 127.0.0.1:12000
    python tcp_client.py 192.168.43.20            # IP del servidor (Parte 7)
    python tcp_client.py 192.168.43.20 "Hola!"    # IP y mensaje
"""
import socket
import sys

SERVER_IP = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
MENSAJE = sys.argv[2] if len(sys.argv) > 2 else "Hola servidor"
SERVER_PORT = 12000

# 1. Crear el socket TCP (operación local).
cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
cliente.settimeout(5)  # evita quedar bloqueado para siempre si el servidor no responde

# 2. Conectarse: acá el sistema operativo envía el SYN y completa el
#    three-way handshake. El puerto local del cliente lo elige el SO.
try:
    cliente.connect((SERVER_IP, SERVER_PORT))
except ConnectionRefusedError:
    sys.exit("[cliente TCP] conexión rechazada: el host respondió, pero nadie escucha en ese puerto (RST)")
except (socket.timeout, TimeoutError):
    sys.exit("[cliente TCP] sin respuesta al intento de conexión (¿firewall? ¿IP equivocada? ¿aislamiento de clientes?)")

ip_local, puerto_local = cliente.getsockname()
print(f"[cliente TCP] conectado a {SERVER_IP}:{SERVER_PORT} desde {ip_local}:{puerto_local}")

# 3. Enviar el mensaje (texto -> bytes).
cliente.sendall(MENSAJE.encode("utf-8"))
print(f"[cliente TCP] enviado: {MENSAJE!r}")

# 4. Recibir la respuesta.
datos = cliente.recv(1024)

# 5. Mostrarla.
print(f"[cliente TCP] respuesta ({len(datos)} bytes): {datos.decode('utf-8', errors='replace')!r}")

# Cerrar: el SO envía un FIN y comienza el cierre de la conexión.
cliente.close()
