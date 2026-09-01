import sys


def cifrar_cesar(texto, corrimiento):
    resultado = []
    for c in texto:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            resultado.append(chr((ord(c) - base + corrimiento) % 26 + base))
        else:
            resultado.append(c)
    return ''.join(resultado)


def main():
    texto = sys.argv[1]
    corrimiento = int(sys.argv[2])
    print(cifrar_cesar(texto, corrimiento))


if __name__ == "__main__":
    main()
