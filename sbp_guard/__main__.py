"""python -m sbp_guard auditar [--sbp CAMINHO] [--sem-ia]
   python -m sbp_guard painel   [--porta 8090]   (painel com botao "Rodar auditoria")"""
import argparse
import sys

from .auditoria import executar, SBP_PADRAO


def main():
    ap = argparse.ArgumentParser(prog="sbp_guard", description="SBP Guard — PII, taint analysis e Risco Cidadão")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("auditar")
    a.add_argument("--sbp", default=SBP_PADRAO, help="pasta do projeto SBP (IoT) a auditar")
    a.add_argument("--sem-ia", action="store_true", help="usa so os alertas prontos, sem chamar o Ollama")
    p = sub.add_parser("painel")
    p.add_argument("--porta", type=int, default=8090)
    p.add_argument("--sbp", default=SBP_PADRAO)
    args = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if args.cmd == "auditar":
        rel = executar(args.sbp, usar_ia=not args.sem_ia,
                       progresso=lambda e: print("[%d/%d] %s" % (e["passo"], e["total"], e["texto"]), flush=True))
        print("\nRisco Cidadão: " + " | ".join("%s %d (%s)" % (k, v["indice"], v["faixa"]) for k, v in rel["risco"].items()))
        print("Painel: painel/index.html  ·  Evidências: evidencias/")
        sys.exit(0 if rel["verificacao"]["ok"] else 2)
    else:
        from .servidor import servir
        servir(args.porta, args.sbp)


if __name__ == "__main__":
    main()
