"""
Camada de acesso ao banco de dados (Supabase / PostgreSQL).

Este módulo isola todo o contato com o Supabase. Nenhum outro arquivo do
projeto deve chamar `supabase.table(...)` diretamente — main.py só importa
e usa as funções definidas aqui.
"""

import os
from datetime import datetime, timezone

from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()  # lê o arquivo .env

supabase: Client = create_client(
    os.environ["SUPABASE_URL"],
    os.environ["SUPABASE_KEY"],
)


# ---------------------------------------------------------------------------
# Cofres
# ---------------------------------------------------------------------------

def inserir_cofre(
    cofre_id: str,
    nome: str,
    kdf_sal: str,
    kdf_iteracoes: int,
    verificador_nonce: str,
    verificador_criptograma: str,
    verificador_etiqueta: str,
) -> None:
    """Cria um novo cofre, já com o verificador (canário) cifrado."""
    supabase.table("cofres").insert({
        "id": cofre_id,
        "nome": nome,
        "kdf_sal": kdf_sal,
        "kdf_iteracoes": kdf_iteracoes,
        "verificador_nonce": verificador_nonce,
        "verificador_criptograma": verificador_criptograma,
        "verificador_etiqueta": verificador_etiqueta,
    }).execute()


def buscar_cofre(cofre_id: str) -> dict | None:
    """Busca um cofre pelo id. Devolve None se não existir."""
    resposta = (
        supabase.table("cofres")
        .select("*")
        .eq("id", cofre_id)
        .execute()
    )
    registros = resposta.data
    return registros[0] if registros else None


# ---------------------------------------------------------------------------
# Segredos
# ---------------------------------------------------------------------------

def inserir_segredo(
    segredo_id: str,
    cofre_id: str,
    titulo: str,
    usuario: str | None,
    url: str | None,
    nonce: str,
    criptograma: str,
    etiqueta: str,
) -> None:
    """Grava um novo segredo cifrado, associado a um cofre."""
    supabase.table("segredos").insert({
        "id": segredo_id,
        "cofre_id": cofre_id,
        "titulo": titulo,
        "usuario": usuario,
        "url": url,
        "nonce": nonce,
        "criptograma": criptograma,
        "etiqueta": etiqueta,
    }).execute()


def listar_segredos(cofre_id: str) -> list[dict]:
    """
    Lista os segredos de um cofre, apenas com metadados.

    Importante: NUNCA usar select("*") aqui. Os campos nonce, criptograma
    e etiqueta não pertencem à listagem — expô-los sem necessidade viola
    o princípio de reduzir ao mínimo os dados devolvidos.
    """
    resposta = (
        supabase.table("segredos")
        .select("id, titulo, usuario, url, criado_em")
        .eq("cofre_id", cofre_id)
        .execute()
    )
    return resposta.data


def buscar_segredo(cofre_id: str, segredo_id: str) -> dict | None:
    """
    Busca um segredo específico, com todos os campos (necessário para
    decifrar). Filtra também por cofre_id, para que um segredo de outro
    cofre nunca seja devolvido por engano.
    """
    resposta = (
        supabase.table("segredos")
        .select("*")
        .eq("id", segredo_id)
        .eq("cofre_id", cofre_id)
        .execute()
    )
    registros = resposta.data
    return registros[0] if registros else None


def atualizar_segredo(
    segredo_id: str,
    nonce: str,
    criptograma: str,
    etiqueta: str,
) -> None:
    """
    Atualiza o criptograma de um segredo existente.

    A camada de criptografia deve sortear um nonce NOVO antes de chamar
    esta função — nunca reaproveite o nonce de uma gravação anterior,
    mesmo em uma atualização.
    """
    supabase.table("segredos").update({
        "nonce": nonce,
        "criptograma": criptograma,
        "etiqueta": etiqueta,
        "atualizado_em": datetime.now(timezone.utc).isoformat(),
    }).eq("id", segredo_id).execute()


def remover_segredo(segredo_id: str) -> None:
    """Remove um segredo do cofre."""
    supabase.table("segredos").delete().eq("id", segredo_id).execute()
