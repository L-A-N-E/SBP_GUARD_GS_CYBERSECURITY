"""SBP — Embarque Assistido, versao 1 (VULNERAVEL DE PROPOSITO, para a auditoria).

Ideia da funcionalidade: no totem, a pessoa com deficiencia le o QR code e pede
"embarque assistido" (o motorista para mais perto, rebaixa o onibus, espera).
O formulario manda nome, CPF, condicao, telefone, ponto e linha.

Esta versao comete os erros classicos de vazamento de dado pessoal:
log com tudo, broker MQTT publico, prompt de IA com CPF, CSV em texto puro
e print no console. Na demonstracao as saidas sao FALSAS (em memoria):
nada aqui e enviado para a internet.
"""
import json
import logging

MQTT_HOST = "broker.hivemq.com"          # broker publico usado pelo totem do SBP
TOPICO = "sbp-gs2026/totem/sbp-0001"
log = logging.getLogger("sbp.embarque")


def enviar_para_ia(ia, prompt):
    return ia(prompt)


def solicitar_embarque(corpo_requisicao, broker, ia, arquivo):
    dados = json.loads(corpo_requisicao)
    log.info("novo pedido de embarque assistido: %s" % dados)

    aviso = {"ponto": dados["ponto"], "linha": dados["linha"], "passageiro": dados["nome"],
             "cpf": dados["cpf"], "condicao": dados["condicao"], "telefone": dados["telefone"]}
    broker.publish(TOPICO + "/embarque", json.dumps(aviso, ensure_ascii=False))

    prioridade = enviar_para_ia(ia, f"Classifique a prioridade do embarque de {dados['nome']}, "
                                    f"CPF {dados['cpf']}, condicao: {dados['condicao']}")

    arquivo.write(f"{dados['cpf']};{dados['nome']};{dados['condicao']};{dados['telefone']}\n")
    print("pedido registrado para", dados["nome"], "tel", dados["telefone"])
    return {"ok": True, "prioridade": prioridade}
