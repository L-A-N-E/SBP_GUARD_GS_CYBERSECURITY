"""Roda o Embarque Assistido com cidadaos ficticios em 3 cenarios e mede os vazamentos.

  antes      versao vulneravel, guardiao so observando (o que vazaria hoje)
  guardiao   versao vulneravel, guardiao BLOQUEANDO cada saida insegura
  corrigido  versao corrigida, guardiao bloqueando (prova que ela nao vaza nada)

Todas as saidas sao falsas (em memoria). Os CPFs sao gerados aqui com digito
verificador valido, mas sao ficticios e nunca saem desta maquina.
"""
import builtins
import io
import json
import logging
import os
import random
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sbp_guard.pii import Motor                                         # noqa: E402
from sbp_guard.taint_runtime import (Guardiao, BrokerProtegido, LogProtegido,  # noqa: E402
                                     IAProtegida, VazamentoBloqueado)
import embarque_vulneravel                                               # noqa: E402
import embarque_seguro                                                   # noqa: E402


def gerar_cpf(rng):
    n = [rng.randint(0, 9) for _ in range(9)]
    for k in (10, 11):
        s = sum(d * (k - i) for i, d in enumerate(n))
        n.append((s * 10) % 11 % 10)
    d = "".join(map(str, n))
    return "%s.%s.%s-%s" % (d[:3], d[3:6], d[6:9], d[9:])


def cidadaos(qtd=4, semente=2026):
    rng = random.Random(semente)
    nomes = ["Ana Beatriz Moura", "Carlos Henrique Dias", "Joana Ribeiro", "Paulo Sérgio Lima", "Rita de Cássia Nunes"]
    cond = ["deficiência visual", "cadeirante", "deficiência auditiva", "mobilidade reduzida", "baixa visão"]
    paradas = [("3703094", "5757-51"), ("2203206", "607C-10")]
    out = []
    for i in range(qtd):
        p, l = paradas[i % 2]
        out.append({"nome": nomes[i % 5], "cpf": gerar_cpf(rng), "condicao": cond[i % 5],
                    "telefone": "(11) 9%04d-%04d" % (rng.randint(1000, 9999), rng.randint(0, 9999)),
                    "ponto": p, "linha": l})
    return out


class BrokerFalso:
    def __init__(self):
        self.mensagens = []

    def publish(self, topico, payload=None, *a, **k):
        self.mensagens.append((topico, payload))


class IAFalsa:
    def __init__(self):
        self.prompts = []

    def __call__(self, prompt):
        self.prompts.append(prompt)
        return "prioridade alta"


class CofreFalso:
    def __init__(self):
        self.itens = {}

    def guardar(self, chave, valor):
        self.itens[chave] = valor


class OperadorFalso:
    def __init__(self, guardiao):
        self.g, self.recebidos = guardiao, []

    def enviar(self, msg):
        self.recebidos.append(self.g.verificar(msg, "operador_autenticado", "canal do motorista"))


class Captura(logging.Handler):
    def __init__(self):
        super().__init__()
        self.linhas = []

    def emit(self, r):
        self.linhas.append(r.getMessage())


def _logger(nome):
    lg = logging.getLogger(nome)
    lg.handlers, lg.propagate, lg.level = [], False, logging.INFO
    cap = Captura()
    lg.addHandler(cap)
    return lg, cap


def _medir_vazamento(motor, broker, cap, ia, arquivo, console):
    """Le tudo o que chegou nas saidas e conta dado pessoal (verdade independente do guardiao)."""
    saidas = {"mqtt_publico": [p for _, p in broker.mensagens], "log": cap.linhas, "llm": ia.prompts,
              "arquivo_texto": arquivo.getvalue().splitlines() if arquivo else [], "console": console}
    res = {}
    for nome, itens in saidas.items():
        n = 0
        for it in itens:
            try:
                obj = json.loads(it)
                ach = motor.analisar_json(obj) if isinstance(obj, (dict, list)) else motor.analisar_texto(str(it))
            except (ValueError, TypeError):
                ach = motor.analisar_texto(str(it))
            n += len(ach)
        res[nome] = n
    return res


def cenario(nome, motor, pessoas):
    modo = {"antes": "monitorar", "guardiao": "bloquear", "corrigido": "bloquear"}[nome]
    g = Guardiao(modo, motor)
    broker, ia, cofre = BrokerFalso(), IAFalsa(), CofreFalso()
    console = []
    arquivo = io.StringIO()
    lg, cap = _logger("sbp.embarque." + nome)
    bloqueios_engolidos = []

    def protegido(fn, *a, **k):
        try:
            return fn(*a, **k)
        except VazamentoBloqueado as e:        # saida descartada, o pedido continua
            bloqueios_engolidos.append(e.evento["destino"])
            return None

    class B:
        def publish(self, t, p=None, *a, **k):
            return protegido(BrokerProtegido(broker, g).publish, t, p)

    class L:
        def info(self, m, *a):
            return protegido(LogProtegido(lg, g).info, m, *a)

    def ia_prot(texto):
        r = protegido(IAProtegida(ia, g), texto)
        return r or "prioridade não calculada (prompt bloqueado)"

    class Arq:
        def write(self, s):
            if protegido(g.verificar, s, "arquivo_texto", "gravação CSV") is not None:
                arquivo.write(s)

    def print_prot(*args, **k):
        texto = " ".join(map(str, args))
        if protegido(g.verificar, texto, "log", "print no console") is not None:
            console.append(texto)

    resultados = []
    if nome in ("antes", "guardiao"):
        embarque_vulneravel.log = L()
        embarque_vulneravel.print = print_prot          # sombreia o print so dentro do modulo
        for p in pessoas:
            resultados.append(embarque_vulneravel.solicitar_embarque(json.dumps(p, ensure_ascii=False), B(), ia_prot, Arq()))
        del embarque_vulneravel.print
    else:
        embarque_seguro.log = L()
        op = OperadorFalso(g)
        for p in pessoas:
            resultados.append(embarque_seguro.solicitar_embarque(json.dumps(p, ensure_ascii=False), B(), ia_prot, cofre, op))

    vaz = _medir_vazamento(motor, broker, cap, ia, arquivo, console)
    return {"cenario": nome, "modo_guardiao": modo, "pedidos": len(pessoas),
            "pedidos_atendidos": sum(1 for r in resultados if r and r.get("ok")),
            "dados_pessoais_que_chegaram_nas_saidas": vaz, "total_vazado": sum(vaz.values()),
            "guardiao": g.resumo(), "eventos": g.eventos,
            "mensagens_broker": len(broker.mensagens), "prompts_ia": len(ia.prompts)}


def rodar(motor=None, qtd=4):
    motor = motor or Motor()
    pessoas = cidadaos(qtd)
    return [cenario(n, motor, pessoas) for n in ("antes", "guardiao", "corrigido")]


if __name__ == "__main__":
    for c in rodar():
        print("%-10s vazou=%-3d bloqueados=%-3d atendidos=%d/%d  por saida=%s" % (
            c["cenario"], c["total_vazado"], c["guardiao"]["bloqueado"], c["pedidos_atendidos"], c["pedidos"],
            c["dados_pessoais_que_chegaram_nas_saidas"]))
