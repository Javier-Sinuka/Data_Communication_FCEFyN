from pathlib import Path

datos = Path("frames.bin").read_bytes()

nombre_grupo = "MiLANesas"
group = nombre_grupo.lower()[:5].encode("ascii")

inicio = 0
paquetes = []

while True:
    posicion = datos.find(group, inicio)

    if posicion == -1:
        break

    seq = datos[posicion + 5]
    length = datos[posicion + 6]

    payload_inicio = posicion + 7
    payload_fin = payload_inicio + length

    payload = datos[payload_inicio:payload_fin]

    paquetes.append((seq, length, payload))

    inicio = posicion + 1

paquetes.sort(key=lambda x: x[0])

for seq, length, payload in paquetes:
    print(
        "SEQ =", seq,
        "LENGTH =", length,
        "PAYLOAD =", payload.decode("ascii")
    )