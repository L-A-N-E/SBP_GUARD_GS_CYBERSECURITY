"""SBP — Embarque Assistido, versao 2 (CORRIGIDA com o SBP Guard).

O que mudou em relacao a versao 1:
  * Minimizacao (LGPD art. 6º, III): o broker publico so recebe ponto, linha,
    um identificador pseudonimo e "precisa de apoio: sim". Nada de nome, CPF ou condicao.
  * Pseudonimizacao: o CPF vira um HMAC-SHA256 com chave secreta (nao da para voltar).
  * O tipo de apoio (visual, cadeira de rodas...) vai so para o canal autenticado
    do motorista, ja reduzido a uma categoria — nunca o diagnostico.
  * Logs e prompt de IA sem nenhum dado pessoal.
  * O registro completo vai criptografado para o cofre.
  * Todas as saidas passam pelo Guardiao (taint em tempo de execucao).
"""
import hashlib
import hmac
import json
import logging
import os

from sbp_guard.taint_runtime import marcar

MQTT_HOST = "broker.hivemq.com"
TOPICO = "sbp-gs2026/totem/sbp-0001"
log = logging.getLogger("sbp.embarque")
CHAVE = os.environ.get("SBP_CHAVE_PSEUDONIMO", "chave-de-demonstracao-troque-em-producao").encode()
ROTULOS = {"nome": "pessoal", "cpf": "pessoal", "telefone": "pessoal", "condicao": "saude"}
CATEGORIAS = {"visual": "apoio_visual", "cego": "apoio_visual", "cegueira": "apoio_visual",
              "cadeira": "cadeira_de_rodas", "cadeirante": "cadeira_de_rodas", "mobilidade": "mobilidade_reduzida",
              "auditiva": "apoio_auditivo", "surd": "apoio_auditivo"}


def pseudonimizar(valor):
    return hmac.new(CHAVE, str(valor).encode(), hashlib.sha256).hexdigest()[:12]


def minimizar_apoio(condicao):
    c = str(condicao).lower()
    for chave, cat in CATEGORIAS.items():
        if chave in c:
            return cat
    return "apoio_geral"


def criptografar(dados):
    # demonstracao: no produto real seria AES-GCM com chave do cofre (KMS)
    return hashlib.sha256(json.dumps(dados, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def enviar_para_ia(ia, prompt):
    return ia(prompt)


def solicitar_embarque(corpo_requisicao, broker, ia, cofre, operador):
    dados = marcar(json.loads(corpo_requisicao), ROTULOS)
    pedido = pseudonimizar(dados["cpf"])
    apoio = minimizar_apoio(dados["condicao"])
    ponto, linha = dados["ponto"], dados["linha"]

    log.info("pedido %s registrado (ponto %s, linha %s)" % (pedido, ponto, linha))
    broker.publish(TOPICO + "/embarque", json.dumps({"ponto": ponto, "linha": linha, "pedido": pedido, "apoio": True}))
    operador.enviar({"pedido": pedido, "ponto": ponto, "linha": linha, "apoio": apoio})
    prioridade = enviar_para_ia(ia, f"Classifique a prioridade de um embarque com {apoio} na linha {linha}")
    cofre.guardar(pedido, criptografar(dados))
    return {"ok": True, "pedido": pedido, "prioridade": prioridade}
