"""Indicador de Risco Cidadão (0 a 100).

Calculado de forma DETERMINISTICA (sem IA), para ser auditavel:
    pontos de cada problema = peso da severidade × peso do tipo de dado × exposicao
    indice = 100 × (1 − e^(−soma/30))
Exposicao = quao publico e o lugar onde o dado chega (broker MQTT publico = 1,0;
log = 0,6; dado parado num arquivo = 0,3). Vazamento bloqueado pelo guardiao em
tempo de execucao vale so 10% (o caminho existe no codigo, mas o dado nao sai).
"""
import math

SEV = {"critica": 10, "alta": 6, "media": 3, "baixa": 1}
CAT = {"saude": 1.0, "credencial": 1.0, "financeiro": 0.9, "identificador": 0.8, "pessoal": 0.8,
       "contato": 0.6, "localizacao": 0.6, "entrada": 0.5}
EXPO = {"mqtt_publico": 1.0, "rede_http": 0.9, "llm": 0.7, "log": 0.6, "resposta_http": 0.6, "mqtt": 0.6,
        "console": 0.5, "arquivo": 0.5, "repouso": 0.3}
SINK_PARA_DESTINO = {"mqtt_publico": "mqtt_publico", "mqtt": "mqtt_publico", "log": "log", "console": "log",
                     "llm": "llm", "arquivo": "arquivo_texto"}
FAIXAS = [(75, "crítico"), (50, "alto"), (25, "moderado"), (0, "baixo")]


def faixa(indice):
    return next(n for lim, n in FAIXAS if indice >= lim)


def calcular(pii, fluxos, destinos_bloqueados=()):
    """Retorna indice, faixa, pontos por categoria e a lista de contribuicoes (para o painel)."""
    contrib = []
    for a in pii:
        contrib.append({"tipo": "dado em repouso", "categoria": a["categoria"], "ref": "%s:%s" % (a["arquivo"], a["linha"]),
                        "pontos": SEV[a["severidade"]] * CAT.get(a["categoria"], 0.5) * EXPO["repouso"]})
    for f in fluxos:
        if f["status"] != "VAZAMENTO":
            continue
        p = SEV[f["severidade"]] * CAT.get(f["fonte"]["tipo"], 0.5) * EXPO.get(f["sink"]["tipo"], 0.5)
        bloqueado = SINK_PARA_DESTINO.get(f["sink"]["tipo"]) in destinos_bloqueados
        contrib.append({"tipo": "fluxo bloqueado" if bloqueado else "fluxo de vazamento", "categoria": f["fonte"]["tipo"],
                        "ref": "%s:%s" % (f["arquivo"], f["sink"]["linha"]), "pontos": p * (0.1 if bloqueado else 1.0)})
    soma = sum(c["pontos"] for c in contrib)
    indice = round(100 * (1 - math.exp(-soma / 30)))
    por_cat = {}
    for c in contrib:
        k = {"pessoal": "identificador", "entrada": "identificador"}.get(c["categoria"], c["categoria"])
        por_cat[k] = round(por_cat.get(k, 0) + c["pontos"], 1)
    return {"indice": indice, "faixa": faixa(indice), "soma": round(soma, 1), "por_categoria": por_cat,
            "contribuicoes": sorted(contrib, key=lambda c: -c["pontos"])}
