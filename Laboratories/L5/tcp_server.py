#!/usr/bin/env python3
"""
Servidor TCP mínimo - TP5 Redes de Computadoras.

Uso:
    python tcp_server.py                 # escucha en 127.0.0.1:12000 (solo esta computadora)
    python tcp_server.py 0.0.0.0         # escucha en todas las interfaces (Parte 7)
    python tcp_server.py 0.0.0.0 12000   # IP y puerto explícitos
"""
import socket
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 12000

# 1. Crear el socket. AF_INET = IPv4, SOCK_STREAM = TCP.
#    Esto es una operación local: todavía no viaja nada por la red.
servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Permite reiniciar el servidor enseguida sin el error "Address already in use"
# (ver TIME_WAIT en la guía). No es imprescindible para entender el resto.
servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# 2. Asociar el socket a una IP y un puerto locales (local, sin tráfico).
servidor.bind((HOST, PORT))

# 3. Pedirle al sistema operativo que acepte conexiones en ese puerto.
#    A partir de acá, un SYN que llegue a este puerto será respondido con SYN-ACK.
servidor.listen(1)
print(f"[servidor TCP] escuchando en {HOST}:{PORT} ...")

# 4. Esperar a que un cliente complete el three-way handshake.
#    accept() devuelve un socket NUEVO, dedicado a esta conexión,
#    y la dirección (IP, puerto) del cliente.
conexion, direccion_cliente = servidor.accept()
print(f"[servidor TCP] conexión aceptada desde {direccion_cliente[0]}:{direccion_cliente[1]}")

# 5. Recibir hasta 1024 bytes. TCP entrega un flujo de bytes: recv() puede
#    devolver menos (o más mensajes juntos) de lo que el cliente envió en un send().
datos = conexion.recv(1024)

# 6. Mostrar lo recibido (bytes -> texto).
mensaje = datos.decode("utf-8", errors="replace")
print(f"[servidor TCP] recibido ({len(datos)} bytes): {mensaje!r}")

# 7. Enviar una respuesta sencilla.
respuesta = f"Recibido: {mensaje}"
conexion.sendall(respuesta.encode("utf-8"))
print(f"[servidor TCP] respuesta enviada: {respuesta!r}")

# Esperar a que el cliente cierre: recv() devuelve b"" cuando llega su FIN.
while conexion.recv(1024):
    pass
print("[servidor TCP] el cliente cerró la conexión")

conexion.close()
servidor.close()
