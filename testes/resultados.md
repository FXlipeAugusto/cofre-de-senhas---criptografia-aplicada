# Resultados dos Testes

## 1. Criação do cofre

A API criou o cofre com sucesso e retornou seu identificador.

### Teste pela API

![Criação do cofre pela API](1_Criando_o_Cofre.png)

### Registro no Supabase

![Cofre armazenado no Supabase](1_Cofre_supabase.png)


## 2. Abertura do cofre

A API verificou a senha mestra corretamente e permitiu a abertura do cofre.

### Teste pela API

![Abertura do cofre pela API](2_Abrindo_o_Cofre.png)


## 3. Criação de segredo

A API criou o segredo com sucesso e retornou seu identificador.

### Teste pela API

![Criação de segredo pela API](3_Criando_o_Segredo.png)

### Registro no Supabase

![Segredo armazenado no Supabase](3_Segredo_supabase.png)


## 4. Listagem de segredos

A API verificou a senha mestra e listou corretamente os segredos armazenados no cofre.

### Teste pela API

![Listagem de segredos pela API](4_Listando_os_Segredos.png)


## 5. Busca e descriptografia

A API recuperou o segredo específico e descriptografou sua senha corretamente.

### Teste pela API

![Busca e descriptografia do segredo](5_Buscando_e_Descriptografando.png)


## 6. Atualização de segredo

A API atualizou corretamente os dados do segredo e gerou uma nova senha criptografada.

### Teste pela API

![Atualização do segredo pela API](6_Atualizando_o_Segredo.png)

### Registro no Supabase

![Segredo atualizado no Supabase](6_Segredo_atualizado_supabase.png)


## 7. Exclusão de segredo

A API removeu o segredo com sucesso do cofre.

### Teste pela API

![Exclusão do segredo pela API](7_Excluindo_o_Segredo.png)

### Registro no Supabase

![Segredo removido do Supabase](7_Segredo_excluido_supabase.png)


## 8. Validação de senha incorreta

A API recusou o acesso ao cofre quando foi fornecida uma senha mestra incorreta.

### Teste pela API

![Validação de senha incorreta](8_Senha_incorreta.png)