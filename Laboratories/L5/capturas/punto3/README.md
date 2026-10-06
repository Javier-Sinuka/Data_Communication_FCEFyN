# Punto 3 — Evidencias TCP/UDP con Ncat

Capturas reales de Wireshark 4.2.2 sobre `lo`, tomadas el 30/09/2026 con Ncat
7.94SVN. Todos los extremos usan IPv4 `127.0.0.1`.

| Archivo | Ensayo | Paquetes |
|---|---|---:|
| tcp_intercambio.pcapng | Tres líneas en cada sentido, con inicio y cierre | 18 |
| udp_intercambio.pcapng | Las mismas seis líneas | 6 |
| tcp_una_frase.pcapng | Una frase, con inicio y cierre | 8 |
| udp_una_frase.pcapng | La misma frase | 1 |
| puertos_cerrados.pcapng | Intentos sin servidores TCP/UDP | 4 |

Para visualizar UDP como datos de Ncat y evitar la interpretación automática
LLC por el puerto 12001, abrir, por ejemplo:

```bash
wireshark -n -r udp_intercambio.pcapng -Y 'udp.port == 12001' -d udp.port==12001,data
```

Esto cambia únicamente la decodificación visual. Las exportaciones auxiliares
`*_analisis.json` conservan la interpretación predeterminada de sharkd; el
encabezado IPv4 indica inequívocamente UDP (17). `resumen_paquetes.tsv`
clasifica según ese campo, sin contar el UDP incluido dentro del error ICMP
como un segundo paquete.

Los archivos `*_stdout.txt` contienen los datos recibidos y los
`*_stderr.txt`, los diagnósticos de Ncat. Los sufijos cliente/servidor indican
el proceso receptor. `eventos.json` registra comandos, escritura de líneas y
señales SIGINT (equivalentes a Ctrl+C). No se usó una implementación propia
de sockets: Python solo coordinó los procesos Ncat y Wireshark.

Las cinco capturas terminaron automáticamente a los 12 segundos. Se dejó un
intervalo sin datos después de iniciar los clientes y se continuó capturando
después de cerrarlos. Las imágenes originales están en `../../img/punto3/`.

## Verificación

```bash
python3 verificar.py
sha256sum -c SHA256SUMS.txt
```

La verificación contrasta los bytes PCAPNG con los exportados por Wireshark,
las longitudes, flags, textos recibidos y el datagrama original citado por
ICMP. No presupone checksums de transporte completos en loopback.

## Repetición en otra carpeta

Con Ncat, Wireshark, permisos de dumpcap y acceso a la sesión gráfica:

```bash
python3 reproducir.py --ncat /ruta/a/ncat --output /tmp/tp5-punto3-nuevo
```

El programa se niega a sobrescribir capturas existentes. Los puertos 12000 y
12001 deben estar libres. La versión utilizada se obtuvo del paquete oficial
Ubuntu `ncat` 7.94+git20230807.3be01efb1+dfsg-3build2, extraído temporalmente;
no se realizó una instalación global. Los puertos efímeros y la segmentación
pueden variar al repetir los ensayos.
