# waxseal

Log de auditoria que **denuncia adulteração** (*tamper-evident*), em Java puro.

Árvore de Merkle (RFC 6962), checkpoints assinados com Ed25519 e testemunhas independentes.
Nenhuma dependência em tempo de execução: só o JDK.

O nome vem do selo de cera (*wax seal*): ele não impede que alguém abra a carta, mas ninguém
a abre sem deixar marca.

É a mesma técnica que sustenta o Certificate Transparency, o banco de checksums do Go e o
Sigstore, aplicada a um problema comum de back-end: o log de auditoria.

## O problema

Um log de auditoria serve para o dia em que algo deu errado. Nesse dia, quem mais quer
alterá-lo costuma ser quem tem acesso de administrador ao servidor.

As defesas usuais não cobrem esse caso:

| Defesa | Por que não basta |
| --- | --- |
| Tabela "somente inserção" na aplicação | Quem acessa o banco ou o disco ignora a aplicação. |
| Checksum por registro | Quem edita o registro recalcula o checksum. |
| Assinar o log | Quem tem a chave reescreve tudo e assina de novo. |

O `waxseal` parte de outra pergunta: em vez de tentar *impedir* a alteração, como tornar
impossível alterar **sem que alguém perceba**, inclusive quando o autor é o próprio operador?

## Demonstração

```bash
./mvnw -q package
```

```bash
java -jar target/waxseal-0.1.0.jar demo
```

```text
1. An application records audit events
   [0] 2026-01-10T09:12:03Z user=ana     action=LOGIN    ip=10.0.0.7
   [1] 2026-01-10T09:14:40Z user=ana     action=TRANSFER amount=100.00 to=acct-7781
   [2] 2026-01-10T09:15:02Z user=root    action=GRANT    role=admin target=mallory
   [3] 2026-01-10T09:20:19Z user=mallory action=EXPORT   table=customers rows=48210
   [4] 2026-01-10T09:21:00Z user=mallory action=LOGOUT
   signed checkpoint: size=5 root=722a7f6a16439fd4...

2. An independent witness stores that checkpoint
   witness now trusts size=5

3. The log grows, and must prove it only appended
   [ok] consistency proof 5 -> 8 accepted (4 hashes)
   [ok] entry 2 proven to be in the log with 3 hashes, without reading the other 7 entries

4. ATTACK A: an intruder edits the file on disk and repairs the checksum
   before: 2026-01-10T09:15:02Z user=root    action=GRANT    role=admin target=mallory
   after:  2026-01-10T09:15:02Z user=root    action=PING     host=db01
   [DETECTED] entries in range [0, 5) were modified: they no longer match the checkpoint signed at size 5

5. ATTACK B: an insider with the signing key rewrites everything and signs it again
   the forged log is internally flawless: 9 entries, valid signature, every hash matches
   [DETECTED by the witness: INCONSISTENT] the log of size 9 does not contain the 8 entries it committed to earlier
```

O ataque B é o ponto do projeto. O log forjado tem assinatura válida e todos os hashes
conferem; nenhuma verificação local o distingue de um log honesto. Ele só é exposto porque
uma testemunha guardou um checkpoint anterior e exige a prova de que o histórico antigo
continua lá.

## Como funciona

**1. Cada entrada vira uma folha de uma árvore de Merkle.** A raiz resume todas as entradas
e a ordem delas: mudar um byte de qualquer entrada muda a raiz.

```text
                  raiz = H(1 | h01 | h23)
                 /                       \
     h01 = H(1 | h0 | h1)         h23 = H(1 | h2 | h3)
       /            \               /            \
h0 = H(0 | e0)  h1 = H(0 | e1)  h2 = H(0 | e2)  h3 = H(0 | e3)
```

Os prefixos `0` (folha) e `1` (nó interno) impedem que alguém apresente a concatenação de
dois hashes como se fosse uma entrada e forje uma prova.

**2. Um checkpoint é a raiz assinada.** O log declara: "minhas primeiras N entradas têm esta
raiz". O formato de texto é canônico: cada checkpoint tem uma única codificação válida.

```text
waxseal-checkpoint-v1
origin: audit.example
size: 3
root: asIE3dtk6U+4tKBFYBO6LbA4QMPWwMZjdUXHqUw3lKI=
time: 1794578865035
sig: fQ63Z1UwH9wzXk7L1ezPPS32zJmsOzleRakukDg0e7mxTbu+YKbAdGVkuHII18FxnIWGaQuwRWY+2TDRDBftBg==
```

**3. Prova de inclusão.** Mostra que uma entrada está no log usando cerca de log₂(N) hashes,
sem ler as outras entradas. Com um milhão de entradas são 20 hashes.

**4. Prova de consistência.** Mostra que o log de tamanho M é o log de tamanho N com
entradas acrescentadas no fim, sem nada alterado, removido ou reordenado antes disso.

**5. Testemunha.** Um processo independente que guarda o último checkpoint que viu e só
aceita o seguinte acompanhado de uma prova de consistência válida. Quem reescreve o
histórico não consegue produzir essa prova, com ou sem a chave de assinatura.

## O que é detectado, e o que não é

| Ataque | Detectado por |
| --- | --- |
| Editar uma entrada no disco, corrigindo o checksum | Verificação local, contra os checkpoints |
| Apagar ou truncar entradas já cobertas por checkpoint | Verificação local |
| Forjar um checkpoint sem a chave | Assinatura |
| Reescrever o log inteiro com a chave e assinar de novo | Testemunha (prova de consistência) |
| Voltar o log a um estado anterior (*rollback*) | Testemunha |
| Assinar dois históricos diferentes do mesmo tamanho | Testemunha |

Limites, ditos com clareza:

- **Detecta, não impede.** Os dados ainda podem ser destruídos; o que deixa de existir é a
  destruição silenciosa. Recuperar o conteúdo exige backup.
- **A verificação local é a primeira linha, não a garantia.** Quem tem acesso total ao
  diretório do log também alcança `checkpoints.txt` e a chave. Contra esse atacante, quem
  protege é a testemunha, que guarda checkpoints fora do alcance dele.
- **Entradas ainda sem checkpoint não estão protegidas.** Quanto mais frequentes os
  checkpoints e as consultas da testemunha, menor a janela.
- **Visões divididas (*split view*).** Um log malicioso pode mostrar históricos diferentes a
  testemunhas diferentes. Detectar isso exige que as testemunhas comparem checkpoints entre
  si (*gossip*), o que este projeto não implementa.
- **O log registra o que recebe.** Um evento que a aplicação nunca enviou, ou um evento
  falso enviado com um token roubado, está fora do alcance dele.
- **A chave fica em arquivo.** Em produção ela pertence a um HSM ou KMS.
- **O primeiro contato da testemunha é TOFU** (*trust on first use*): a impressão digital da
  chave precisa ser conferida por outro canal.
- O servidor HTTP embutido não faz TLS nem limita requisições; deve ficar atrás de um proxy.

## Uso

Requer JDK 21 ou superior.

```text
waxseal demo                          roda a demonstração de ataque e detecção
waxseal init <dir> <origin>           cria um log e sua chave de assinatura
waxseal append <dir> <texto>          acrescenta uma entrada
waxseal checkpoint <dir>              assina e imprime o estado atual
waxseal verify <dir>                  confere as entradas contra os checkpoints assinados
waxseal prove <dir> <index>           imprime e confere uma prova de inclusão
waxseal serve <dir> [porta]           serve o log por HTTP em 127.0.0.1
waxseal witness <url> <state-dir>     audita um log remoto, lembrando o que já viu
```

`waxseal` aqui é `java -jar target/waxseal-0.1.0.jar`. O código de saída `2` significa que
adulteração ou mau comportamento do log foi detectado.

### API HTTP

```text
GET  /v1/checkpoint                         último checkpoint assinado
GET  /v1/pubkey                             chave pública do log (base64, X.509)
GET  /v1/entries/{index}                    entrada, em bytes
POST /v1/entries                            acrescenta o corpo da requisição
GET  /v1/proofs/inclusion?index=I&size=N    prova de inclusão, um hash base64 por linha
GET  /v1/proofs/consistency?from=M&to=N     prova de consistência, um hash base64 por linha
```

A leitura é pública de propósito: é o que permite a terceiros auditar o log. A escrita exige
`Authorization: Bearer <token>`, definido pela variável de ambiente `WAXSEAL_TOKEN`.

### Como biblioteca

```java
try (TransparencyLog log = TransparencyLog.create(Path.of("audit"), "audit.example")) {
    long index = log.append("user=ana action=LOGIN".getBytes(StandardCharsets.UTF_8));
    Checkpoint checkpoint = log.checkpoint();

    List<byte[]> proof = log.inclusionProof(index, checkpoint.treeSize());
    boolean included = ProofVerifier.verifyInclusion(index, checkpoint.treeSize(),
            Hashing.leafHash(log.entry(index)), proof, checkpoint.rootHash());
}
```

## Decisões de projeto

- **Gerador e verificador de provas não compartilham código.** As provas são geradas pela
  definição recursiva da RFC 6962 (`MerkleTree`) e conferidas pelo algoritmo iterativo da
  RFC 9162 (`ProofVerifier`). Um erro em um lado não se esconde no outro.
- **Provas em O(log n).** A árvore guarda o hash de cada subárvore completa, então raízes e
  provas de qualquer tamanho passado não exigem reler as entradas.
- **Evidência não é modificada.** Um registro incompleto no fim do arquivo (queda no meio de
  uma escrita) só é descartado depois que o arquivo passa na verificação. Se a verificação
  falha, nada no disco é tocado.
- **Corrupção e adulteração são erros diferentes.** `CorruptLogException` indica dano
  acidental, pego pelo checksum; `TamperedLogException` indica contradição com um checkpoint
  assinado. A segunda mensagem informa entre quais checkpoints a alteração ocorreu.
- **Um tamanho, uma assinatura.** O log não assina dois checkpoints para o mesmo tamanho.
- **Token comparado em tempo constante**, depois de passar os dois lados por SHA-256, para
  não vazar conteúdo nem comprimento pelo tempo de resposta.
- **Erros HTTP não ecoam a entrada** nem expõem detalhes internos; entradas são servidas como
  `application/octet-stream` com `nosniff`.
- **Zero dependências.** SHA-256, Ed25519, servidor e cliente HTTP vêm do JDK. Menos
  dependências, menos superfície na cadeia de suprimentos.

## Testes

```bash
./mvnw verify
```

A suíte tem 41 testes, entre eles:

- as raízes de referência do conjunto de testes do Certificate Transparency;
- todas as provas de inclusão e de consistência para todos os tamanhos de árvore até 70,
  geradas por um algoritmo e conferidas pelo outro;
- provas adulteradas, truncadas, com elementos a mais e de históricos reescritos, todas
  rejeitadas;
- edição, truncamento e checkpoint forjado no disco;
- recuperação de escrita interrompida;
- testemunha contra *rollback*, bifurcação e histórico reescrito com a chave verdadeira;
- o fluxo completo por HTTP, incluindo autenticação.

## Referências

- [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962): Certificate Transparency
- [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162): Certificate Transparency Version 2.0
- Crosby e Wallach, *Efficient Data Structures for Tamper-Evident Logging*, USENIX Security 2009
