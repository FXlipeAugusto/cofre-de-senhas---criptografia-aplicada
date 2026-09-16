from fastapi import FastAPI, Header, HTTPException

from app.modelos import NovoCofre, NovoSegredo
from app import banco
from app import cripto


app = FastAPI(title="Cofre de Senhas")


# ---------------------------------------------------------------------------
# Criar cofre
# ---------------------------------------------------------------------------

@app.post("/cofres", status_code=201)
def criar_cofre(dados: NovoCofre):

    sal = cripto.gerar_sal()

    chave = cripto.derivar_chave(
        dados.senha_mestra,
        sal,
        cripto.ITERACOES_PADRAO
    )

    # Gera o ID do cofre
    import uuid

    cofre_id = str(uuid.uuid4())

    # Cria o verificador antes de salvar o cofre
    nonce, criptograma, etiqueta = cripto.criar_verificador(
        chave,
        cofre_id
    )

    banco.inserir_cofre(
        cofre_id,
        dados.nome,
        cripto.para_b64(sal),
        cripto.ITERACOES_PADRAO,
        nonce,
        criptograma,
        etiqueta
    )

    return {"id": cofre_id}


# ---------------------------------------------------------------------------
# Abrir cofre
# ---------------------------------------------------------------------------

@app.post("/cofres/{cofre_id}/abrir")
def abrir_cofre(
    cofre_id: str,
    x_senha_mestra: str = Header(...)
):

    cofre = banco.buscar_cofre(cofre_id)

    if cofre is None:
        raise HTTPException(
            status_code=404,
            detail="Cofre não encontrado"
        )

    sal = cripto.de_b64(cofre["kdf_sal"])

    chave = cripto.derivar_chave(
        x_senha_mestra,
        sal,
        cofre["kdf_iteracoes"]
    )

    correta = cripto.senha_mestra_correta(
        chave,
        cofre["verificador_nonce"],
        cofre["verificador_criptograma"],
        cofre["verificador_etiqueta"],
        cofre_id
    )

    if not correta:
        raise HTTPException(
            status_code=401,
            detail="Senha mestra incorreta"
        )

    return {
        "mensagem": "Cofre aberto com sucesso"
    }


# ---------------------------------------------------------------------------
# Criar segredo
# ---------------------------------------------------------------------------

@app.post("/cofres/{cofre_id}/segredos", status_code=201)
def criar_segredo(
    cofre_id: str,
    dados: NovoSegredo,
    x_senha_mestra: str = Header(...)
):

    cofre = banco.buscar_cofre(cofre_id)

    if cofre is None:
        raise HTTPException(
            status_code=404,
            detail="Cofre não encontrado"
        )

    sal = cripto.de_b64(cofre["kdf_sal"])

    chave = cripto.derivar_chave(
        x_senha_mestra,
        sal,
        cofre["kdf_iteracoes"]
    )

    correta = cripto.senha_mestra_correta(
        chave,
        cofre["verificador_nonce"],
        cofre["verificador_criptograma"],
        cofre["verificador_etiqueta"],
        cofre_id
    )

    if not correta:
        raise HTTPException(
            status_code=401,
            detail="Senha mestra incorreta"
        )

    # Gera o ID do segredo
    import uuid

    segredo_id = str(uuid.uuid4())

    aad = f"{cofre_id}|{segredo_id}".encode()

    nonce, criptograma, etiqueta = cripto.cifrar(
        chave,
        dados.senha,
        aad
    )

    banco.inserir_segredo(
        segredo_id,
        cofre_id,
        dados.titulo,
        dados.usuario,
        dados.url,
        nonce,
        criptograma,
        etiqueta
    )

    return {"id": segredo_id}


# ---------------------------------------------------------------------------
# Listar segredos
# ---------------------------------------------------------------------------

@app.get("/cofres/{cofre_id}/segredos")
def listar_segredos(
    cofre_id: str,
    x_senha_mestra: str = Header(...)
):

    cofre = banco.buscar_cofre(cofre_id)

    if cofre is None:
        raise HTTPException(
            status_code=404,
            detail="Cofre não encontrado"
        )

    sal = cripto.de_b64(cofre["kdf_sal"])

    chave = cripto.derivar_chave(
        x_senha_mestra,
        sal,
        cofre["kdf_iteracoes"]
    )

    correta = cripto.senha_mestra_correta(
        chave,
        cofre["verificador_nonce"],
        cofre["verificador_criptograma"],
        cofre["verificador_etiqueta"],
        cofre_id
    )

    if not correta:
        raise HTTPException(
            status_code=401,
            detail="Senha mestra incorreta"
        )

    return banco.listar_segredos(cofre_id)


# ---------------------------------------------------------------------------
# Buscar um segredo específico
# ---------------------------------------------------------------------------

@app.get("/cofres/{cofre_id}/segredos/{segredo_id}")
def buscar_segredo(
    cofre_id: str,
    segredo_id: str,
    x_senha_mestra: str = Header(...)
):

    cofre = banco.buscar_cofre(cofre_id)

    if cofre is None:
        raise HTTPException(
            status_code=404,
            detail="Cofre não encontrado"
        )

    sal = cripto.de_b64(cofre["kdf_sal"])

    chave = cripto.derivar_chave(
        x_senha_mestra,
        sal,
        cofre["kdf_iteracoes"]
    )

    correta = cripto.senha_mestra_correta(
        chave,
        cofre["verificador_nonce"],
        cofre["verificador_criptograma"],
        cofre["verificador_etiqueta"],
        cofre_id
    )

    if not correta:
        raise HTTPException(
            status_code=401,
            detail="Senha mestra incorreta"
        )

    segredo = banco.buscar_segredo(
        cofre_id,
        segredo_id
    )

    if segredo is None:
        raise HTTPException(
            status_code=404,
            detail="Segredo não encontrado"
        )

    aad = f"{cofre_id}|{segredo_id}".encode()

    senha = cripto.decifrar(
        chave,
        segredo["nonce"],
        segredo["criptograma"],
        segredo["etiqueta"],
        aad
    )

    return {
        "id": segredo["id"],
        "titulo": segredo["titulo"],
        "usuario": segredo["usuario"],
        "url": segredo["url"],
        "senha": senha
    }


# ---------------------------------------------------------------------------
# Atualizar segredo
# ---------------------------------------------------------------------------

@app.put("/cofres/{cofre_id}/segredos/{segredo_id}")
def atualizar_segredo(
    cofre_id: str,
    segredo_id: str,
    dados: NovoSegredo,
    x_senha_mestra: str = Header(...)
):

    cofre = banco.buscar_cofre(cofre_id)

    if cofre is None:
        raise HTTPException(
            status_code=404,
            detail="Cofre não encontrado"
        )

    sal = cripto.de_b64(cofre["kdf_sal"])

    chave = cripto.derivar_chave(
        x_senha_mestra,
        sal,
        cofre["kdf_iteracoes"]
    )

    correta = cripto.senha_mestra_correta(
        chave,
        cofre["verificador_nonce"],
        cofre["verificador_criptograma"],
        cofre["verificador_etiqueta"],
        cofre_id
    )

    if not correta:
        raise HTTPException(
            status_code=401,
            detail="Senha mestra incorreta"
        )

    segredo = banco.buscar_segredo(
        cofre_id,
        segredo_id
    )

    if segredo is None:
        raise HTTPException(
            status_code=404,
            detail="Segredo não encontrado"
        )

    aad = f"{cofre_id}|{segredo_id}".encode()

    # Cria uma nova senha criptografada com um novo nonce
    nonce, criptograma, etiqueta = cripto.cifrar(
        chave,
        dados.senha,
        aad
    )

    # Atualiza título, usuário, URL e senha no Supabase
    banco.atualizar_segredo(
        segredo_id,
        dados.titulo,
        dados.usuario,
        dados.url,
        nonce,
        criptograma,
        etiqueta
    )

    return {
        "mensagem": "Segredo atualizado com sucesso"
    }


# ---------------------------------------------------------------------------
# Excluir segredo
# ---------------------------------------------------------------------------

@app.delete("/cofres/{cofre_id}/segredos/{segredo_id}")
def remover_segredo(
    cofre_id: str,
    segredo_id: str,
    x_senha_mestra: str = Header(...)
):

    cofre = banco.buscar_cofre(cofre_id)

    if cofre is None:
        raise HTTPException(
            status_code=404,
            detail="Cofre não encontrado"
        )

    sal = cripto.de_b64(cofre["kdf_sal"])

    chave = cripto.derivar_chave(
        x_senha_mestra,
        sal,
        cofre["kdf_iteracoes"]
    )

    correta = cripto.senha_mestra_correta(
        chave,
        cofre["verificador_nonce"],
        cofre["verificador_criptograma"],
        cofre["verificador_etiqueta"],
        cofre_id
    )

    if not correta:
        raise HTTPException(
            status_code=401,
            detail="Senha mestra incorreta"
        )

    segredo = banco.buscar_segredo(
        cofre_id,
        segredo_id
    )

    if segredo is None:
        raise HTTPException(
            status_code=404,
            detail="Segredo não encontrado"
        )

    banco.remover_segredo(segredo_id)

    return {
        "mensagem": "Segredo removido com sucesso"
    }