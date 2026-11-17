"""Pipeline completo do SBP Guard: PII -> taint estatico -> taint em runtime -> risco -> IA -> painel."""
import hashlib
import json
import os
import sys
import time

from . import avaliacao, risco
from .ia import Tradutor, MODELO
from .pii import Motor, SEV_ORDEM
from .taint_estatico import analisar_arquivo, analisar_pasta

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SBP_PADRAO = os.path.join(os.path.dirname(RAIZ), "GS2026_IOT_S.P.B")
IGNORAR_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}
CAT_PT = {"credencial": "credencial", "saude": "saúde", "pessoal": "dado pessoal", "entrada": "dado do cidadão",
          "identificador": "identificador", "contato": "contato", "financeiro": "financeiro", "localizacao": "localização"}


def _id(*partes):
    return hashlib.sha1("|".join(map(str, partes)).encode()).hexdigest()[:10]


def _gitignore_tem_env(raiz):
    p = os.path.join(raiz, ".gitignore")
    try:
        return any(l.strip() in (".env", "*.env", "/.env") for l in open(p, encoding="utf-8"))
    except OSError:
        return False


def varrer_pii(motor, raiz, segredos):
    protegido = _gitignore_tem_env(raiz)
    achados, n_arq, n_bytes = [], 0, 0
    for d, ds, fs in os.walk(raiz):
        ds[:] = [x for x in ds if x not in IGNORAR_DIRS]
        for f in sorted(fs):
            p = os.path.join(d, f)
            rel = os.path.relpath(p, raiz).replace("\\", "/")
            try:
                n_bytes += os.path.getsize(p)
            except OSError:
                continue
            n_arq += 1
            for a in motor.analisar_arquivo(p, rel, protegido_git=protegido):
                segredos.add(a._valor)
                d_ = a.publico()
                d_["id"] = _id(rel, a.linha, a.regra, a.impressao)
                achados.append(d_)
    achados.sort(key=lambda a: (-SEV_ORDEM[a["severidade"]], a["arquivo"], a["linha"]))
    return achados, n_arq, n_bytes


def agrupar_fluxos(fluxos):
    g = {}
    for f in fluxos:
        k = (f["arquivo"], f["sink"]["linha"], f["sink"]["tipo"])
        if k not in g:
            g[k] = dict(f, id=_id(*k), dados=set(), fontes=[])
        x = g[k]
        x["dados"].add(CAT_PT.get(f["fonte"]["tipo"], f["fonte"]["tipo"]))
        x["fontes"].append("L%d · %s" % (f["fonte"]["linha"], f["fonte"]["descricao"]))
        if SEV_ORDEM[f["severidade"]] > SEV_ORDEM[x["severidade"]]:
            x.update({"severidade": f["severidade"], "fonte": f["fonte"], "explicacao": f["explicacao"], "parcial": f["parcial"]})
    out = []
    for x in g.values():
        x["dados"] = sorted(x["dados"])
        x["fontes"] = sorted(set(x["fontes"]))
        out.append(x)
    out.sort(key=lambda f: (-SEV_ORDEM[f["severidade"]], f["arquivo"], f["sink"]["linha"]))
    return out


def executar(sbp=SBP_PADRAO, saida=None, usar_ia=True, progresso=print):
    t0 = time.time()
    saida = saida or os.path.join(RAIZ, "painel")
    evid = os.path.join(RAIZ, "evidencias")
    os.makedirs(saida, exist_ok=True)
    os.makedirs(evid, exist_ok=True)
    segredos = set()
    passo = lambda n, txt: progresso({"passo": n, "total": 8, "texto": txt})

    passo(1, "Carregando regras do motor PII")
    motor = Motor()
    passo(1, "%d regras de texto + %d regras de campo carregadas (regras_pii.json)" % (len(motor.regras), len(motor.chaves)))

    passo(2, "Medindo a robustez do motor com o corpus rotulado")
    metricas = avaliacao.avaliar(motor)
    passo(2, "Precisão %.1f%% · recall %.1f%% em %d amostras" % (100 * metricas["geral"]["precisao"], 100 * metricas["geral"]["recall"],
                                                              metricas["amostras_positivas"] + metricas["amostras_negativas"]))

    alvos = []
    if sbp and os.path.isdir(sbp):
        passo(3, "Varrendo o SBP real (código, firmware, painel, dados GTFS, .env)")
        pii, n_arq, n_bytes = varrer_pii(motor, sbp, segredos)
        passo(3, "%d arquivos (%.1f MB) lidos · %d dado(s) sensível(is) encontrado(s)" % (n_arq, n_bytes / 1e6, len(pii)))
        passo(4, "Taint analysis no código Python do SBP")
        fl, san = analisar_pasta(sbp, motor)
        passo(4, "%d fluxo(s) de vazamento · %d sanitização(ões) reconhecida(s)" % (sum(f["status"] == "VAZAMENTO" for f in fl), len(san)))
        alvos.append({"id": "sbp", "nome": "SBP — código real do totem e do servidor", "caminho": os.path.basename(sbp),
                      "arquivos": n_arq, "megabytes": round(n_bytes / 1e6, 1), "pii": pii, "fluxos": fl,
                      "fluxos_agrupados": agrupar_fluxos(fl), "sanitizados": san})
    else:
        passo(3, "SBP real não encontrado em %s — pulando" % sbp)

    passo(5, "Auditando o protótipo Embarque Assistido (v1 vulnerável e v2 corrigida)")
    proto = os.path.join(RAIZ, "prototipo")
    for vid, arq, nome in (("v1", "embarque_vulneravel.py", "Embarque Assistido v1 (vulnerável)"),
                           ("v2", "embarque_seguro.py", "Embarque Assistido v2 (corrigida)")):
        p = os.path.join(proto, arq)
        fl, san = analisar_arquivo(p, "prototipo/" + arq, motor)
        pii = [dict(a.publico(), id=_id(arq, a.linha, a.regra)) for a in motor.analisar_arquivo(p, "prototipo/" + arq)]
        alvos.append({"id": vid, "nome": nome, "caminho": "prototipo/" + arq, "arquivos": 1, "pii": pii, "fluxos": fl,
                      "fluxos_agrupados": agrupar_fluxos(fl), "sanitizados": san})
        passo(5, "%s: %d fluxo(s) de vazamento, %d sanitização(ões)" % (nome, sum(f["status"] == "VAZAMENTO" for f in fl), len(san)))

    passo(6, "Taint em tempo de execução: 4 pedidos fictícios em 3 cenários")
    sys.path.insert(0, proto)
    import demo_runtime
    runtime = demo_runtime.rodar(motor)
    for p in demo_runtime.cidadaos(4):                  # os dados ficticios tambem nao podem aparecer no relatorio
        segredos |= {p["cpf"], p["telefone"], p["nome"], p["cpf"].replace(".", "").replace("-", "")}
    for c in runtime:
        passo(6, "%-9s → %d dado(s) pessoal(is) chegaram nas saídas · %d saída(s) bloqueada(s)" % (
            c["cenario"], c["total_vazado"], c["guardiao"]["bloqueado"]))

    passo(7, "Calculando o Risco Cidadão")
    A = {a["id"]: a for a in alvos}
    g = next(c for c in runtime if c["cenario"] == "guardiao")
    bloqueados = {e["destino"] for e in g["eventos"] if e["acao"] == "bloqueado"} if g["total_vazado"] == 0 else set()
    indices = {
        "antes": risco.calcular(A["v1"]["pii"], A["v1"]["fluxos"]),
        "guardiao": risco.calcular(A["v1"]["pii"], A["v1"]["fluxos"], bloqueados),
        "corrigido": risco.calcular(A["v2"]["pii"], A["v2"]["fluxos"]),
    }
    if "sbp" in A:
        indices["sbp"] = risco.calcular(A["sbp"]["pii"], A["sbp"]["fluxos"])
    passo(7, " · ".join("%s %d" % (k, v["indice"]) for k, v in indices.items()))

    tr = Tradutor(os.path.join(RAIZ, "cache_ia.json"), usar_ia=usar_ia)
    itens = []
    for a in alvos:
        for f in a["fluxos_agrupados"]:
            if f["status"] == "VAZAMENTO":
                itens.append(f)
        for p in a["pii"]:
            if p["categoria"] in ("credencial", "saude", "financeiro") or SEV_ORDEM[p["severidade"]] >= 2:
                itens.append(p)
    passo(8, "IA (%s) traduzindo %d falha(s) em alertas para o cidadão" % ("Ollama · " + MODELO if tr.usar_ia else "modelo pronto", len(itens)))
    alertas = {}
    for i, it in enumerate(itens, 1):
        alertas[it["id"]] = tr.traduzir(it)
        passo(8, "[%d/%d] %s" % (i, len(itens), alertas[it["id"]]["titulo"]))

    rel = {"gerado_em": time.strftime("%d/%m/%Y %H:%M:%S"), "duracao_s": round(time.time() - t0, 1),
           "regras": {"texto": len(motor.regras), "campos": len(motor.chaves)},
           "metricas_pii": metricas, "alvos": alvos, "runtime": runtime, "risco": indices,
           "destinos_bloqueados": sorted(bloqueados), "alertas": alertas,
           "ia": {"modelo": MODELO, "local": True, "usada": tr.usar_ia, "estatisticas": tr.estatisticas}}

    texto = json.dumps(rel, ensure_ascii=False, indent=1, default=list)
    with open(os.path.join(saida, "relatorio.json"), "w", encoding="utf-8") as f:
        f.write(texto)
    with open(os.path.join(saida, "relatorio.js"), "w", encoding="utf-8") as f:
        f.write("window.RELATORIO = " + texto + ";\n")
    _evidencias(rel, evid)
    rel["verificacao"] = verificar_sem_segredos([saida, evid, os.path.join(RAIZ, "cache_ia.json")], segredos)
    with open(os.path.join(evid, "verificacao_sem_segredos.txt"), "w", encoding="utf-8") as f:
        f.write(rel["verificacao"]["texto"])
    texto = json.dumps(rel, ensure_ascii=False, indent=1, default=list)
    with open(os.path.join(saida, "relatorio.json"), "w", encoding="utf-8") as f:
        f.write(texto)
    with open(os.path.join(saida, "relatorio.js"), "w", encoding="utf-8") as f:
        f.write("window.RELATORIO = " + texto + ";\n")
    passo(8, "Pronto em %.1f s · %s" % (time.time() - t0, rel["verificacao"]["resumo"]))
    return rel


def verificar_sem_segredos(caminhos, segredos):
    """Garante que nenhum valor bruto encontrado (ex.: o token real do .env) foi parar nos arquivos gerados."""
    arquivos = []
    for c in caminhos:
        if os.path.isfile(c):
            arquivos.append(c)
        elif os.path.isdir(c):
            for d, _, fs in os.walk(c):
                arquivos += [os.path.join(d, f) for f in fs if not f.endswith((".png", ".mp4", ".webm"))]
    vaz = []
    for a in arquivos:
        try:
            t = open(a, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        for s in segredos:
            if len(s) >= 6 and s in t:
                vaz.append((os.path.basename(a), hashlib.sha256(s.encode()).hexdigest()[:8]))
    ok = not vaz
    resumo = "nenhum valor sensível nos arquivos gerados" if ok else "%d VALOR(ES) SENSÍVEL(IS) VAZARAM" % len(vaz)
    texto = "Verificação automática de vazamento nos artefatos do SBP Guard\n%s\n\n" % time.strftime("%d/%m/%Y %H:%M")
    texto += "Valores sensíveis encontrados na varredura (guardados só em memória): %d\n" % len(segredos)
    texto += "Arquivos gerados verificados: %d\n" % len(arquivos)
    texto += "Resultado: %s\n" % ("OK — " + resumo if ok else "FALHA — " + resumo)
    for a, h in vaz:
        texto += "  - %s contém o valor de impressão #%s\n" % (a, h)
    return {"ok": ok, "resumo": resumo, "arquivos": len(arquivos), "valores": len(segredos), "texto": texto}


def _evidencias(rel, evid):
    L = []
    for a in rel["alvos"]:
        L.append("=" * 100)
        L.append("ALVO: %s  (%s)" % (a["nome"], a["caminho"]))
        L.append("=" * 100)
        L.append("\n[Motor PII] %d achado(s)" % len(a["pii"]))
        for p in a["pii"]:
            L.append("  %-8s %-34s %s:%s  %s  %s" % (p["severidade"].upper(), p["nome"], p["arquivo"], p["linha"], p["mascara"], p.get("nota", "")))
        L.append("\n[Taint analysis] %d fluxo(s)" % len(a["fluxos"]))
        for f in a["fluxos"]:
            L.append("  %-10s %-8s FONTE %s:%d  %s" % (f["status"], f["severidade"].upper(), f["arquivo"], f["fonte"]["linha"], f["fonte"]["descricao"]))
            L.append("  %-19s  SINK  %s:%d  %s" % ("", f["arquivo"], f["sink"]["linha"], f["sink"]["descricao"]))
            L.append("  %-19s        %s" % ("", f["sink"]["codigo"]))
        L.append("\n[Sanitizações reconhecidas] %d" % len(a["sanitizados"]))
        for s in a["sanitizados"]:
            L.append("  %s:%d  %s  (%s)" % (s["arquivo"], s["linha"], s["codigo"], ", ".join(s["tipos"])))
        L.append("")
    open(os.path.join(evid, "taint_estatico.txt"), "w", encoding="utf-8").write("\n".join(L))

    R = ["Taint em tempo de execução — Embarque Assistido com 4 pedidos fictícios", ""]
    for c in rel["runtime"]:
        R.append("-" * 100)
        R.append("CENÁRIO %s (guardião em modo %s)" % (c["cenario"].upper(), c["modo_guardiao"]))
        R.append("  pedidos atendidos: %d/%d" % (c["pedidos_atendidos"], c["pedidos"]))
        R.append("  dados pessoais que chegaram em cada saída: %s" % c["dados_pessoais_que_chegaram_nas_saidas"])
        R.append("  ações do guardião: %s" % c["guardiao"])
        for e in c["eventos"][:12]:
            R.append("    %s  %-26s %-14s %-30s detectado por %s  %s" % (
                e["quando"], e["acao"], e["destino"], ", ".join(e["categorias"]), e["detectado_por"],
                "; ".join("%s=%s" % (i["tipo"], i["mascara"]) for i in e["itens"][:3])))
        if len(c["eventos"]) > 12:
            R.append("    ... +%d eventos" % (len(c["eventos"]) - 12))
    open(os.path.join(evid, "taint_runtime.txt"), "w", encoding="utf-8").write("\n".join(R))
    json.dump(rel["metricas_pii"], open(os.path.join(evid, "metricas_motor_pii.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    A = ["Alertas gerados pela IA (%s, local) — o que cada falha significa para o cidadão" % rel["ia"]["modelo"], ""]
    for k, v in rel["alertas"].items():
        A.append("[%s] %s  (%s · fonte: %s)" % (k, v["titulo"], v["severidade"], v.get("fonte", "")))
        A.append("   Risco para o cidadão: " + v["risco_cidadao"])
        A.append("   Impacto: " + v["impacto"])
        A.append("   Como corrigir: " + v["como_corrigir"])
        A.append("")
    open(os.path.join(evid, "alertas_ia.txt"), "w", encoding="utf-8").write("\n".join(A))
