"""Servidor local do painel: http://127.0.0.1:8090  (so escuta na propria maquina).
POST /api/auditar dispara a auditoria; GET /api/progresso mostra o passo a passo."""
import json
import os
import threading
import webbrowser
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

from .auditoria import executar, RAIZ

ESTADO = {"rodando": False, "eventos": [], "erro": ""}
TRAVA = threading.Lock()


def _rodar(sbp):
    try:
        executar(sbp, progresso=lambda e: ESTADO["eventos"].append(e))
    except Exception as e:                                  # mostra no painel, sem detalhe interno
        ESTADO["erro"] = type(e).__name__
    finally:
        ESTADO["rodando"] = False


class Handler(SimpleHTTPRequestHandler):
    sbp = None

    def __init__(self, *a, **k):
        super().__init__(*a, directory=os.path.join(RAIZ, "painel"), **k)

    def log_message(self, *a):
        pass

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def _json(self, cod, obj):
        corpo = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(cod)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)

    def do_GET(self):
        if self.path.startswith("/api/progresso"):
            return self._json(200, ESTADO)
        return super().do_GET()

    def do_POST(self):
        if self.path != "/api/auditar":
            return self._json(404, {"erro": "rota inexistente"})
        with TRAVA:
            if ESTADO["rodando"]:
                return self._json(409, {"erro": "auditoria já em andamento"})
            ESTADO.update(rodando=True, eventos=[], erro="")
        threading.Thread(target=_rodar, args=(self.sbp,), daemon=True).start()
        return self._json(202, {"ok": True})


def servir(porta=8090, sbp=None, abrir=True):
    Handler.sbp = sbp
    srv = ThreadingHTTPServer(("127.0.0.1", porta), Handler)
    url = "http://127.0.0.1:%d/" % porta
    print("[sbp-guard] painel em", url, "(Ctrl+C para sair)", flush=True)
    if abrir:
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
