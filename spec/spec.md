# Especificação Técnica: Interface Web para UFW (ufw2me)

## 1. Visão Geral

O objetivo deste projeto é construir uma interface web leve e intuitiva para gerenciar regras do `ufw` (Uncomplicated Firewall). O design, estética e experiência de usuário devem ser altamente inspirados na interface de gerenciamento de firewall da Hetzner Cloud Console (ver screenshots de referência fornecidos na pasta `/tmp`).

## 2. Requisitos de Infraestrutura e Arquitetura

- **Instalação "One Line":** A implantação do sistema deve suportar um comando prático de instalação única via terminal, seguindo o formato:
    ```bash
    curl -fsSL https://xxx.com/install.sh | sudo bash
    ```
- **Backend UFW:** O serviço `ufw` deve estar instalado e ativo no servidor. O script de instalação "one line" deve verificar a presença do UFW e assumir sua ativação/instalação automática caso necessário.
- **Porta de Acesso:** A aplicação web deve ser exposta na porta `9850` por padrão. Esse valor deve ser configurável via arquivo de configuração (ex: `.env`, `.yaml`, etc).
- **Dependências Mínimas:** A escolha da tecnologia deve priorizar a **menor quantidade possível de dependências** no sistema hospedeiro.
    - _Recomendação:_ Utilizar abordagens como um binário único (ex: Go que empacote o frontend) ou stacks leves de execução autossuficiente (como um servidor simples servindo a API para uma SPA estática sem pesadas toolchains Node ou bibliotecas de runtime).

## 3. Funcionalidades da Interface

### 3.1. Estrutura Geral e Layout

- **Tema Visual:** Utilizar um tema escuro (Dark Theme), com opção para light e system, limpo e moderno, usando a paleta de cores, tipografia e espaçamentos contidos nas imagens.
- **Abas Menores:** É necessário apresentar indicadores contextuais sobre listagem de regras e interfaces de rede. Seguindo a especificação ("Listar as interfaces"), a UI deverá ter um espaço informando ou filtrando a qual interface de rede a regra se aplica (ex: `eth0`).

### 3.2. Listagem de Regras (Inbound / Outbound)

- O layout deve dividir visualmente as regras em seções bloqueadas e agrupadas sob os títulos **INBOUND** e **OUTBOUND**.
- **Ordenação:** Porque a ordem das regras em firewalls tem um peso primordial, a interface **deve permitir reordenação**. As regras devem poder ser manipuladas para mudar sua prioridade (exemplo: arrastar-e-soltar ou controles estruturados de mover para cima/baixo).

### 3.3. Elementos e Campos de uma Regra

Cada bloco de regra da linha deve emular a aparência do painel do Hetzner, contendo:

- **Descrição da regra (Contexto visual):** Um campo de texto descritivo (ex: "Any HTTP", "Postgres - Fernando IP", ou placeholder "Add description").
- **Inputs de Rede/IP:** Campo para informar IPs de origem/destino com suporte a visualização em formato de _tags/badges_ (ex: "Any IPv4", "143.0.190.9", "201.92.92.185"). O usuário pode ter a possibilidade de inserir IPs específicos ou atalhos (IPv4 global, IPv6, etc).
- **Protocolo:** Um seletor de lista suspensa (dropdown box). _Valores aceitos conforme imagem:_ `TCP`, `UDP`, `ICMP`, `GRE`, `ESP`.
- **Porta (Inicial / Final):** Input permitindo a injeção da porta (ou range de portas) onde a regra é aplicada.

### 3.4. Fluxo de Edição / Aplicação

- **Botão Add Rule:** Botão suspenso no cabeçalho ("Add rule") com opções em submenu flutuante: "Incoming" (Entrada) ou "Outgoing" (Saída). Também devem existir links embutidos no final de cada grupo (ex: linha vazia com "+ Add rule").
- **Ações nas Regras:** Botão na extremidade do card para excluir (delete, ícone `X`).
- **Confirmação Lógica de Alterações:** Mudanças de regras feitas via interface não salvam instantaneamente em background de forma silenciosa ou síncrona, exigindo confirmação de usuário se implementado à risca pela barra de rodapé (Botões _Cancel_ e _Save changes_ na parte inferior da tela antes que o reload do UFW execute os comandos de sistema).
