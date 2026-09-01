import sys

from scapy.all import rdpcap, IP, ICMP

VERDE = "\033[92m"
RESET = "\033[0m"

# Firma de los paquetes craft de pingv4.py: 16 bytes de timeval (variables,
# no se pueden matchear por valor) + char + 39 bytes de patron fijo
# 0x11..0x37 al final. El timeval real de un ping legitimo tambien varia,
# asi que la firma se valida solo por longitud y por el patron fijo
# (posicion 17 en adelante), no por el contenido del timeval.
PAYLOAD_LEN = 56
TIMEVAL_LEN = 16
PATTERN = bytes(range(0x10, 0x38))
PATTERN_RESTO = PATTERN[1:]  # 39 bytes: 0x11..0x37 (el 0x10 fue reemplazado por el char)

# Palabras funcionales muy comunes en espanol (articulos, preposiciones,
# conjunciones, pronombres). Sirven como "ancla" porque casi cualquier frase
# en espanol las contiene, y es muy improbable que aparezcan por azar al
# descifrar con un corrimiento incorrecto.
PALABRAS_COMUNES = {
    "de", "la", "el", "en", "y", "que", "los", "del", "con", "una", "un",
    "para", "por", "es", "al", "se", "su", "no", "como", "mas", "o", "pero",
    "sus", "le", "ya", "este", "son", "entre", "cuando", "muy", "sin",
    "sobre", "tambien", "me", "hasta", "hay", "donde", "quien", "desde",
    "todo", "nos", "todos", "uno", "les", "ni", "contra", "esa", "esto",
    "esta", "estas", "estos", "seguridad", "redes", "criptografia",
}

# Frecuencia relativa aproximada de letras en espanol (%), usada como
# criterio secundario (desempate) mediante distancia chi-cuadrado.
FRECUENCIA_ES = {
    'a': 12.53, 'b': 1.42, 'c': 4.68, 'd': 5.86, 'e': 13.68, 'f': 0.69,
    'g': 1.01, 'h': 0.70, 'i': 6.25, 'j': 0.44, 'k': 0.02, 'l': 4.97,
    'm': 3.15, 'n': 6.71, 'o': 8.68, 'p': 2.51, 'q': 0.88, 'r': 6.87,
    's': 7.98, 't': 4.63, 'u': 3.93, 'v': 0.90, 'w': 0.02, 'x': 0.22,
    'y': 0.90, 'z': 0.52,
}


def extraer_texto_cifrado(archivo):
    paquetes = rdpcap(archivo)

    caracteres = []
    for pkt in paquetes:
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
            payload = bytes(pkt[ICMP].payload)
            if len(payload) != PAYLOAD_LEN:
                continue
            if payload[TIMEVAL_LEN + 1:] != PATTERN_RESTO:
                continue
            caracteres.append(chr(payload[TIMEVAL_LEN]))

    texto = "".join(caracteres)

    # Solo se descartan espacios de arranque/cierre (padding accidental);
    # los espacios internos del mensaje se conservan intactos.
    return texto.strip(" ")


def descifrar_cesar(texto, corrimiento):
    resultado = []
    for c in texto:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            resultado.append(chr((ord(c) - base - corrimiento) % 26 + base))
        else:
            resultado.append(c)
    return "".join(resultado)


def puntaje_palabras(texto):
    palabras = texto.lower().split()
    if not palabras:
        return 0
    coincidencias = sum(1 for p in palabras if p.strip(".,;:!?") in PALABRAS_COMUNES)
    return coincidencias / len(palabras)


def puntaje_frecuencia(texto):
    letras = [c.lower() for c in texto if c.isalpha()]
    if not letras:
        return float("inf")
    total = len(letras)
    conteo = {l: 0 for l in FRECUENCIA_ES}
    for l in letras:
        if l in conteo:
            conteo[l] += 1
    chi2 = 0.0
    for l, freq_esperada in FRECUENCIA_ES.items():
        observado = (conteo[l] / total) * 100
        chi2 += (observado - freq_esperada) ** 2 / freq_esperada
    return chi2


def mejor_corrimiento(candidatos):
    # 1er criterio: mas coincidencias con palabras funcionales comunes.
    # 2do criterio (desempate): menor chi-cuadrado frente a la frecuencia
    # tipica de letras del espanol (texto en espanol real se parece mas
    # a esa distribucion que un texto descifrado con corrimiento erroneo).
    mejor = max(
        candidatos,
        key=lambda item: (puntaje_palabras(item[1]), -puntaje_frecuencia(item[1])),
    )
    return mejor[0]


def main():
    archivo = sys.argv[1]
    texto_cifrado = extraer_texto_cifrado(archivo)

    print(f"[DEBUG] texto cifrado reconstruido ({len(texto_cifrado)} chars): {texto_cifrado!r}")

    candidatos = [(c, descifrar_cesar(texto_cifrado, c)) for c in range(26)]
    corrimiento_ganador = mejor_corrimiento(candidatos)

    for corrimiento, texto in candidatos:
        linea = f"{corrimiento:2d}: {texto}"
        if corrimiento == corrimiento_ganador:
            print(f"{VERDE}{linea}{RESET}")
        else:
            print(linea)

    print(f"Llave encontrada: {corrimiento_ganador}")


if __name__ == "__main__":
    main()
