"""SBP — Embarque Assistido, versao 2 (CORRIGIDA com o SBP Guard).

O que mudou em relacao a versao 1:
  * Minimizacao (LGPD art. 6º, III): o broker publico so recebe ponto, linha,
    um identificador pseudonimo e "precisa de apoio: sim". Nada de nome, CPF ou condicao.
  * Pseudonimizacao: o CPF vira um HMAC-SHA256 com chave secreta (nao da para voltar).
  * O tipo de apoio (visual, cadeira de rodas...) vai so para o canal autenticado
    do motorista, ja reduzido a uma categoria — nunca o diagnostico.
  * Logs e prompt de IA sem nenhum dado pessoal.
  * O registro completo vai criptografado para o cofre.
  * Middleware de entrada: interceptar_entrada() marca sozinho cada campo com PII.
  * Erro de validacao nunca devolve o dado do cidadao; o app recebe uma mensagem humana.
  * Todas as saidas passam pelo Guardiao (taint em tempo de execucao).
"""
import hashlib
import hmac
import json
import logging
import os

from sbp_guard.taint_runtime import interceptar_entrada

MQTT_HOST = "broker.hivemq.com"
TOPICO = "sbp-gs2026/totem/sbp-0001"
log = logging.getLogger("sbp.embarque")
CHAVE = os.environ.get("SBP_CHAVE_PSEUDONIMO", "chave-de-demonstracao-troque-em-producao").encode()
CATEGORIAS = {"visual": "apoio_visual", "cego": "apoio_visual", "cegueira": "apoio_visual",
              "cadeira": "cadeira_de_rodas", "cadeirante": "cadeira_de_rodas", "mobilidade": "mobilidade_reduzida",
              "auditiva": "apoio_auditivo", "surd": "apoio_auditivo"}


class PedidoInvalido(Exception):
    pass


MENSAGEM_ERRO = ("Não conseguimos registrar seu pedido de embarque assistido porque faltou uma informação. "
                 "Seus dados não foram compartilhados com ninguém; tente de novo ou peça ajuda no totem.")


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
    dados, _ = interceptar_entrada(json.loads(corpo_requisicao))
    faltando = [c for c in ("cpf", "condicao", "ponto", "linha") if not dados.get(c)]
    if faltando:
        raise PedidoInvalido("campo obrigatório ausente: " + ", ".join(faltando))
    pedido = pseudonimizar(dados["cpf"])
    apoio = minimizar_apoio(dados["condicao"])
    ponto, linha = dados["ponto"], dados["linha"]

    log.info("pedido %s registrado (ponto %s, linha %s)" % (pedido, ponto, linha))
    broker.publish(TOPICO + "/embarque", json.dumps({"ponto": ponto, "linha": linha, "pedido": pedido, "apoio": True}))
    operador.enviar({"pedido": pedido, "ponto": ponto, "linha": linha, "apoio": apoio})
    prioridade = enviar_para_ia(ia, f"Classifique a prioridade de um embarque com {apoio} na linha {linha}")
    cofre.guardar(pedido, criptografar(dados))
    return {"ok": True, "pedido": pedido, "prioridade": prioridade}


def responder_ao_app(corpo_requisicao, broker, ia, cofre, operador):
    """Endpoint POST /api/embarque: o erro tecnico fica no servidor; o app recebe uma frase humana."""
    try:
        return 200, solicitar_embarque(corpo_requisicao, broker, ia, cofre, operador)
    except PedidoInvalido as e:
        log.info("pedido recusado: %s" % e)
        return 400, {"mensagem": MENSAGEM_ERRO}
