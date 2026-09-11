import base64

# Base64 converte binários em string de texto ASCII,
# que será extremamente útil para armazenar os dados.

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Essas bibliotecas fornecem funções fundamentais
# para trabalhar com criptografia AES.

ITERACOES_PADRAO = 210_000
TAMANHO_CHAVE = 32
TAMANHO_SAL = 16
TAMANHO_NONCE = 12


def para_b64(dados: bytes) -> str:
    """Converte bytes em texto Base64, para gravar no banco."""
    return base64.b64encode(dados).decode("ascii")


def de_b64(texto: str) -> bytes:
    """Converte texto Base64 de volta para bytes, ao ler do banco."""
    return base64.b64decode(texto)


def derivar_chave(
    senha_mestra: str,
    sal: bytes,
    iteracoes: int
) -> bytes:

    return PBKDF2(
        senha_mestra,
        sal,
        dkLen=TAMANHO_CHAVE,
        count=iteracoes,
        hmac_hash_module=SHA256
    )


def gerar_sal() -> bytes:
    """Sorteia um sal novo para um cofre."""
    return get_random_bytes(TAMANHO_SAL)


# O sal gerado é uma sequência de 16 bytes aleatórios.


def cifrar(
    chave: bytes,
    texto_claro: str,
    aad: bytes
) -> tuple[str, str, str]:

    nonce = get_random_bytes(TAMANHO_NONCE)

    cifra = AES.new(
        chave,
        AES.MODE_GCM,
        nonce=nonce
    )

    cifra.update(aad)

    texto_bytes = texto_claro.encode("utf-8")

    criptograma, etiqueta = cifra.encrypt_and_digest(texto_bytes)

    return (
        para_b64(nonce),
        para_b64(criptograma),
        para_b64(etiqueta)
    )


def decifrar(
    chave: bytes,
    nonce_b64: str,
    cripto_b64: str,
    etiqueta_b64: str,
    aad: bytes
) -> str:

    nonce = de_b64(nonce_b64)
    criptograma = de_b64(cripto_b64)
    etiqueta = de_b64(etiqueta_b64)

    cifra = AES.new(
        chave,
        AES.MODE_GCM,
        nonce=nonce
    )

    cifra.update(aad)

    texto_claro = cifra.decrypt_and_verify(
        criptograma,
        etiqueta
    )

    return texto_claro.decode("utf-8")


FRASE_VERIFICADORA = "cofre-ok"


def criar_verificador(
    chave: bytes,
    cofre_id: str
) -> tuple[str, str, str]:

    return cifrar(
        chave,
        FRASE_VERIFICADORA,
        cofre_id.encode()
    )


def senha_mestra_correta(
    chave,
    nonce,
    cripto,
    etiqueta,
    cofre_id
) -> bool:

    try:
        texto = decifrar(
            chave,
            nonce,
            cripto,
            etiqueta,
            cofre_id.encode()
        )

        return texto == FRASE_VERIFICADORA

    except ValueError:
        return False