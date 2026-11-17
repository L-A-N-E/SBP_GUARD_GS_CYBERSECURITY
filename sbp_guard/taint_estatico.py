"""Taint analysis estatico (AST) para codigo Python.

Marca como "contaminado" todo valor que vem de uma FONTE de dado sensivel
(variavel de ambiente com segredo, .env, corpo de requisicao, payload MQTT,
parametro chamado cpf/senha/condicao...) e segue esse valor por atribuicoes,
f-strings, concatenacoes, json.dumps, dicionarios e atributos de classe.
Quando ele chega num SINK (print, log, MQTT, arquivo, rede, LLM) sem passar
por um SANITIZADOR (mascarar, anonimizar, hash, .replace(segredo, "***")),
vira um FLUXO no relatorio, com a linha da fonte e a linha do vazamento.
"""
import ast
import os
import re

from .pii import Motor, SEV_ORDEM

PARAMS_SENSIVEIS = {
    "credencial": r"^(senha|password|passwd|token|api_?key|segredo|secret)$",
    "saude": r"^(condicao|condicao_saude|deficiencia|diagnostico|cid|cns|cartao_sus|laudo)$",
    "pessoal": r"^(cpf|nome_completo|nome_passageiro|telefone|celular|email|nascimento|dados_pessoais|passageiro|paciente)$",
    "entrada": r"^(corpo|corpo_requisicao|payload|dados_formulario|formulario|requisicao)$",
}
SEGREDO_ENV = re.compile(r"(TOKEN|SECRET|SENHA|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE|CHAVE)", re.I)
SANITIZADOR = re.compile(r"(mascar|anonimiz|pseudonimiz|ofusc|redact|minimiz|hash|sha\d+|md5|blake|hmac|criptograf|encrypt)", re.I)
NEUTRAS = {"len", "bool", "isinstance", "type", "id", "hasattr", "callable", "range", "enumerate_len"}
LLM = re.compile(r"(llm|gpt|openai|ollama|chat_?completion|enviar_para_ia|perguntar_ia|consultar_ia|prompt_ia)", re.I)
LOG_METODOS = {"debug", "info", "warning", "warn", "error", "critical", "exception", "log"}
LOCAL = re.compile(r"^https?://(localhost|127\.0\.0\.1|\[::1\])", re.I)

PESO_ROTULO = {"credencial": 3.0, "saude": 3.0, "pessoal": 2.0, "entrada": 1.5}
PESO_SINK = {"mqtt_publico": 3.0, "rede_http": 3.0, "llm": 2.5, "log": 2.0, "mqtt": 1.5,
             "console": 1.5, "arquivo": 1.5, "resposta_http": 1.5, "rede_https": 0.0}
DESC_SINK = {
    "mqtt_publico": "publicação em broker MQTT público (qualquer pessoa pode assinar o tópico)",
    "mqtt": "publicação MQTT",
    "rede_http": "requisição de rede que pode sair em HTTP sem criptografia",
    "rede_https": "requisição HTTPS para destino autorizado",
    "llm": "envio para modelo de IA (LLM)",
    "log": "registro em log",
    "console": "saída no console/terminal (vai parar em logs)",
    "arquivo": "gravação em arquivo",
    "resposta_http": "resposta HTTP para o navegador",
}
DESC_ROTULO = {"credencial": "credencial/segredo", "saude": "dado de saúde (sensível, LGPD art. 11)",
               "pessoal": "dado pessoal", "entrada": "dado enviado pelo cidadão"}


class Rotulo:
    __slots__ = ("tipo", "linha", "origem", "parcial")

    def __init__(self, tipo, linha, origem, parcial=False):
        self.tipo, self.linha, self.origem, self.parcial = tipo, linha, origem, parcial

    def chave(self):
        return (self.tipo, self.linha, self.origem, self.parcial)

    def __eq__(self, o):
        return self.chave() == o.chave()

    def __hash__(self):
        return hash(self.chave())

    def como_parcial(self):
        return Rotulo(self.tipo, self.linha, self.origem, True)


def _nome(no):
    """'self.http.open' para Attribute/Name; '' para outros."""
    if isinstance(no, ast.Name):
        return no.id
    if isinstance(no, ast.Attribute):
        b = _nome(no.value)
        return (b + "." if b else "") + no.attr
    if isinstance(no, ast.Call):
        return _nome(no.func) + "()"
    return ""


def _constantes(no):
    return [n.value for n in ast.walk(no) if isinstance(n, ast.Constant) and isinstance(n.value, str)]


class Modulo:
    def __init__(self, arvore, arquivo, politica, motor):
        self.arvore, self.arquivo, self.politica, self.motor = arvore, arquivo, politica, motor
        self.atrib_classe = {}         # "Classe.self.token" -> set(Rotulo)
        self.retornos = {}             # nome da funcao -> set(Rotulo)
        self.globais = {}              # nome -> no AST do valor (para resolver URLs)
        self.fluxos = {}
        self.sanitizados = {}
        self.consts = set(_constantes(arvore))
        self.mqtt_publico = any(h in c for c in self.consts for h in politica["brokers_publicos"])
        for st in arvore.body:
            if isinstance(st, ast.Assign):
                for t in st.targets:
                    if isinstance(t, ast.Name):
                        self.globais.setdefault(t.id, []).append(st.value)

    def analisar(self):
        funcoes = []
        for no in ast.walk(self.arvore):
            if isinstance(no, ast.ClassDef):
                for f in no.body:
                    if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        funcoes.append((no.name, f))
        dentro = {id(f) for _, f in funcoes}
        for no in ast.walk(self.arvore):
            if isinstance(no, (ast.FunctionDef, ast.AsyncFunctionDef)) and id(no) not in dentro:
                funcoes.append((None, no))
        for passada in range(4):                       # ponto fixo: atributos de classe e retornos
            self.registrar = passada == 3
            for classe, f in funcoes:
                Funcao(self, classe, f).rodar()
            Funcao(self, None, None).rodar()           # codigo no nivel do modulo
        return list(self.fluxos.values()), list(self.sanitizados.values())


class Funcao:
    def __init__(self, mod, classe, no):
        self.mod, self.classe, self.no = mod, classe, no
        self.estado = {}
        self.lacos = {}                                 # var do for -> expressao iterada
        self.locais = {}
        self.campos = {}                                # var -> {tipo: {campos sensiveis lidos dela}}

    def rodar(self):
        if self.no is None:
            corpo = [s for s in self.mod.arvore.body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        else:
            corpo = self.no.body
            for a in self.no.args.args + self.no.args.kwonlyargs:
                for tipo, pad in PARAMS_SENSIVEIS.items():
                    if re.match(pad, a.arg, re.I):
                        self.estado[a.arg] = {Rotulo(tipo, self.no.lineno, "parâmetro '%s'" % a.arg)}
        for _ in range(2):
            self._bloco(corpo)

    # ------------------------------------------------------------ estado
    def _get(self, nome):
        if nome.startswith("self.") and self.classe:
            return self.mod.atrib_classe.get(self.classe + "." + nome, set())
        return self.estado.get(nome, set())

    def _set(self, alvo, rot, valor=None):
        if isinstance(alvo, (ast.Tuple, ast.List)):
            for e in alvo.elts:
                self._set(e, rot)
            return
        if isinstance(alvo, ast.Starred):
            return self._set(alvo.value, rot)
        if isinstance(alvo, ast.Subscript):              # d["cpf"] = x  -> d fica contaminado
            return self._set(alvo.value, rot | self._get(_nome(alvo.value)))
        n = _nome(alvo)
        if not n:
            return
        if valor is not None:
            self.locais.setdefault(n, []).append(valor)
        if n.startswith("self.") and self.classe:
            k = self.classe + "." + n
            self.mod.atrib_classe[k] = self.mod.atrib_classe.get(k, set()) | rot
        elif rot:
            self.estado[n] = self.estado.get(n, set()) | rot

    # ------------------------------------------------------------ comandos
    def _bloco(self, corpo):
        for st in corpo:
            self._cmd(st)

    def _cmd(self, st):
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        if isinstance(st, ast.Assign):
            r = self.taint(st.value)
            for t in st.targets:
                self._set(t, r, st.value)
        elif isinstance(st, (ast.AnnAssign, ast.AugAssign)) and st.value is not None:
            r = self.taint(st.value)
            if isinstance(st, ast.AugAssign):
                r = r | self._get(_nome(st.target))
            self._set(st.target, r, st.value)
        elif isinstance(st, (ast.For, ast.AsyncFor)):
            r = self.taint(st.iter)
            if isinstance(st.iter, ast.Call) and _nome(st.iter.func) == "open" and self._abre_env(st.iter):
                r = r | {Rotulo("credencial", st.lineno, "leitura do arquivo .env")}
            if isinstance(st.target, ast.Name):
                self.lacos[st.target.id] = st.iter
            self._set(st.target, r)
            self._bloco(st.body + st.orelse)
        elif isinstance(st, (ast.With, ast.AsyncWith)):
            for it in st.items:
                r = self.taint(it.context_expr)
                if it.optional_vars is not None:
                    if isinstance(it.context_expr, ast.Call) and _nome(it.context_expr.func) == "open" and self._abre_env(it.context_expr):
                        r = r | {Rotulo("credencial", st.lineno, "leitura do arquivo .env")}
                    self._set(it.optional_vars, r)
            self._bloco(st.body)
        elif isinstance(st, (ast.If, ast.While)):
            self.taint(st.test)
            self._bloco(st.body + st.orelse)
        elif isinstance(st, ast.Try) or type(st).__name__ == "TryStar":
            self._bloco(st.body)
            for h in st.handlers:
                self._bloco(h.body)
            self._bloco(st.orelse + st.finalbody)
        elif isinstance(st, ast.Return) and st.value is not None and self.no is not None:
            r = self.taint(st.value)
            if r:
                self.mod.retornos[self.no.name] = self.mod.retornos.get(self.no.name, set()) | r
        elif isinstance(st, ast.Expr):
            self.taint(st.value)
        elif isinstance(st, ast.Match) if hasattr(ast, "Match") else False:
            for c in st.cases:
                self._bloco(c.body)

    def _abre_env(self, chamada):
        for a in chamada.args[:1]:
            consts = _constantes(a) + [c for v in self._valores(a) for c in _constantes(v)]
            if any(c.endswith(".env") or c == ".env" for c in consts):
                return True
        return False

    def _valores(self, expr):
        """Expressoes que podem ter dado valor aos nomes usados em expr (para resolver URLs/caminhos)."""
        out, vistos = [], set()

        def visita(e, prof=0):
            for n in ast.walk(e):
                if isinstance(n, ast.Name) and n.id not in vistos and prof < 4:
                    vistos.add(n.id)
                    for v in self.locais.get(n.id, []) + self.mod.globais.get(n.id, []):
                        out.append(v)
                        visita(v, prof + 1)
                    if n.id in self.lacos:
                        out.append(self.lacos[n.id])
                        visita(self.lacos[n.id], prof + 1)
        visita(expr)
        return out

    # ------------------------------------------------------------ expressoes
    def taint(self, e):
        if e is None:
            return set()
        if isinstance(e, ast.Name):
            r = set(self._get(e.id))
            if r and e.id in self.campos:                   # objeto inteiro que tem campos sensiveis
                ex = next(iter(r))
                r |= {Rotulo(t, ex.linha, "objeto '%s' inteiro (contém %s)" % (e.id, ", ".join(sorted(ks))))
                      for t, ks in self.campos[e.id].items()}
            return r
        if isinstance(e, ast.Attribute):
            n = _nome(e)
            if n.endswith(".payload") or n in ("request.json", "request.form", "request.args", "request.data"):
                return {Rotulo("entrada", e.lineno, "dado recebido (%s)" % n)} | self.taint(e.value)
            if n.startswith("self.") and n.count(".") == 1:
                return set(self._get(n))
            return self.taint(e.value)
        if isinstance(e, ast.Subscript):
            base = set(self._get(e.value.id)) if isinstance(e.value, ast.Name) else self.taint(e.value)
            n = _nome(e.value)
            if n == "os.environ":
                return self._fonte_env(e.slice, e.lineno)
            if isinstance(e.slice, ast.Slice):
                self.taint(e.slice.lower), self.taint(e.slice.upper)
                return {r.como_parcial() for r in base}
            k = e.slice.value if isinstance(e.slice, ast.Constant) and isinstance(e.slice.value, str) else None
            self.taint(e.slice)
            if base and k:
                c = self.mod.motor.regra_de_chave(k)
                if c:
                    tipo = {"credencial": "credencial", "saude": "saude"}.get(c["categoria"], "pessoal")
                    if isinstance(e.value, ast.Name):
                        self.campos.setdefault(e.value.id, {}).setdefault(tipo, set()).add(k)
                    return {Rotulo(tipo, r.linha, "%s → campo '%s'" % (r.origem, k), r.parcial) for r in base}
                # campo comum (ex.: j["ponto"]) de uma entrada generica: nao e dado pessoal
                return {r for r in base if r.tipo != "entrada"}
            return base
        if isinstance(e, ast.Call):
            return self._chamada(e)
        if isinstance(e, ast.JoinedStr):
            return set().union(*[self.taint(v) for v in e.values]) if e.values else set()
        if isinstance(e, ast.FormattedValue):
            return self.taint(e.value)
        if isinstance(e, ast.BinOp):
            return self.taint(e.left) | self.taint(e.right)
        if isinstance(e, ast.BoolOp):
            return set().union(*[self.taint(v) for v in e.values])
        if isinstance(e, ast.IfExp):
            self.taint(e.test)
            return self.taint(e.body) | self.taint(e.orelse)
        if isinstance(e, (ast.Compare, ast.UnaryOp)):
            for f in ast.iter_child_nodes(e):
                if isinstance(f, ast.expr):
                    self.taint(f)
            return set()
        if isinstance(e, ast.Dict):
            r = set()
            for k, v in zip(e.keys, e.values):
                rv = self.taint(v)
                if rv and isinstance(k, ast.Constant) and isinstance(k.value, str):
                    c = self.mod.motor.regra_de_chave(k.value)
                    if c:
                        tipo = {"credencial": "credencial", "saude": "saude"}.get(c["categoria"], "pessoal")
                        rv = {Rotulo(tipo, x.linha, x.origem if x.origem.endswith("campo '%s'" % k.value) or "→ campo" in x.origem
                                     else "%s → campo '%s'" % (x.origem, k.value), x.parcial) for x in rv}
                r |= rv | self.taint(k)
            return r
        if isinstance(e, (ast.List, ast.Tuple, ast.Set)):
            return set().union(*[self.taint(v) for v in e.elts]) if e.elts else set()
        if isinstance(e, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            r = set()
            for g in e.generators:
                ri = self.taint(g.iter)
                self._set(g.target, ri)
                r |= ri
            elts = [e.key, e.value] if isinstance(e, ast.DictComp) else [e.elt]
            return r | set().union(*[self.taint(x) for x in elts])
        if isinstance(e, (ast.Starred, ast.Await)):
            return self.taint(e.value)
        if isinstance(e, ast.NamedExpr):
            r = self.taint(e.value)
            self._set(e.target, r)
            return r
        if isinstance(e, ast.Lambda):
            return set()
        return set()

    def _fonte_env(self, chave_no, linha):
        k = chave_no.value if isinstance(chave_no, ast.Constant) and isinstance(chave_no.value, str) else ""
        if SEGREDO_ENV.search(k):
            return {Rotulo("credencial", linha, "variável de ambiente %s" % k)}
        return set()

    def _chamada(self, c):
        n = _nome(c.func)
        curto = n.rsplit(".", 1)[-1]
        args = list(c.args) + [k.value for k in c.keywords]
        # fontes
        if n in ("os.getenv", "os.environ.get", "environ.get", "getenv"):
            for a in args:
                self.taint(a)
            return self._fonte_env(c.args[0], c.lineno) if c.args else set()
        if n in ("input", "getpass.getpass", "getpass"):
            return {Rotulo("credencial" if "getpass" in n else "entrada", c.lineno, "%s()" % n)}
        if n.endswith("rfile.read") or n in ("request.get_json", "request.get_data", "request.form.get", "request.args.get"):
            return {Rotulo("entrada", c.lineno, "corpo da requisição HTTP")}
        # sanitizadores
        if SANITIZADOR.search(curto) or SANITIZADOR.search(n.rsplit(".", 2)[0] if "." in n else ""):
            interno = set().union(*[self.taint(a) for a in args]) if args else set()
            if interno:
                self._sanitizou(c, interno)
            return set()
        if curto == "replace" and isinstance(c.func, ast.Attribute) and c.args and self.taint(c.args[0]):
            base = self.taint(c.func.value)
            self._sanitizou(c, self.taint(c.args[0]))
            return base - self.taint(c.args[0])
        if n in NEUTRAS:
            for a in args:
                self.taint(a)
            return set()
        tainted_args = [self.taint(a) for a in args]
        todos = set().union(*tainted_args) if tainted_args else set()
        alvo = self.taint(c.func.value) if isinstance(c.func, ast.Attribute) else set()
        self._sink(c, n, curto, args, tainted_args, alvo)
        if curto in ("Request", "urlopen", "open", "get", "post", "put", "patch", "delete", "request") and \
                (n.startswith(("urllib", "requests", "httpx", "self.http", "session", "self.session")) or n in ("Request", "urlopen")):
            return set()                                # a resposta da rede nao e o segredo que enviamos
        if curto in self.mod.retornos and not isinstance(c.func, ast.Attribute) or \
           (isinstance(c.func, ast.Attribute) and _nome(c.func.value) == "self" and curto in self.mod.retornos):
            return todos | alvo | self.mod.retornos[curto]
        return todos | alvo

    def _sanitizou(self, c, rot):
        if not self.mod.registrar:
            return
        k = (c.lineno, c.col_offset)
        self.mod.sanitizados[k] = {"arquivo": self.mod.arquivo, "linha": c.lineno,
                                   "codigo": _trecho(c), "tipos": sorted({r.tipo for r in rot})}

    # ------------------------------------------------------------ sinks
    def _sink(self, c, n, curto, args, tainted_args, alvo):
        tipo, dados = None, set()
        if n == "print":
            tipo, dados = "console", set().union(*tainted_args) if tainted_args else set()
        elif curto in LOG_METODOS and isinstance(c.func, ast.Attribute) and re.search(r"(log|logger|logging)", _nome(c.func.value), re.I):
            tipo, dados = "log", set().union(*tainted_args) if tainted_args else set()
        elif curto == "publish":
            tipo = "mqtt_publico" if self.mod.mqtt_publico else "mqtt"
            dados = set().union(*tainted_args[1:2]) if len(tainted_args) > 1 else set()
            dados |= set().union(*[self.taint(k.value) for k in c.keywords if k.arg == "payload"])
        elif curto == "write" and (n.endswith("wfile.write")):
            tipo, dados = "resposta_http", set().union(*tainted_args) if tainted_args else set()
        elif curto in ("write", "writelines", "writerow", "writerows") or n in ("json.dump",):
            tipo, dados = "arquivo", (tainted_args[0] if tainted_args else set())
        elif LLM.search(curto):
            tipo, dados = "llm", set().union(*tainted_args) if tainted_args else set()
        elif n in ("urllib.request.Request", "urllib.request.urlopen", "urlopen", "Request") or \
                re.match(r"^(requests|httpx|session|self\.session)\.(get|post|put|patch|delete|request)$", n):
            dados = set().union(*tainted_args) if tainted_args else set()
            tipo = self._classifica_rede(c.args[0] if c.args else (c.keywords[0].value if c.keywords else None))
        if not tipo or not dados or not self.mod.registrar:
            return
        for r in dados:
            k = (c.lineno, tipo, r.tipo, r.linha, r.parcial)
            if k in self.mod.fluxos:
                continue
            self.mod.fluxos[k] = self._fluxo(c, tipo, r)

    def _classifica_rede(self, url):
        if url is None:
            return "rede_http"
        consts = _constantes(url) + [x for v in self._valores(url) for x in _constantes(v)]
        urls = [x for x in consts if x.startswith(("http://", "https://"))]
        if any(u.startswith("http://") and not LOCAL.match(u) for u in urls):
            return "rede_http"
        if urls and all(u.startswith("https://") or LOCAL.match(u) for u in urls):
            return "rede_https"
        return "rede_http"

    def _fluxo(self, c, tipo, r):
        peso = PESO_ROTULO[r.tipo] * PESO_SINK[tipo] * (0.3 if r.parcial else 1.0)
        sev = "critica" if peso >= 7.5 else "alta" if peso >= 4.5 else "media" if peso >= 2.5 else "baixa"
        status = "PERMITIDO" if tipo == "rede_https" else "VAZAMENTO"
        if tipo == "rede_https":
            sev = "baixa"
        expl = "%s de %s chega em %s" % ("Parte" if r.parcial else "Valor", DESC_ROTULO[r.tipo], DESC_SINK[tipo])
        if tipo == "rede_http":
            expl += ": a lista de URLs inclui http:// — o dado trafega sem criptografia se o HTTPS falhar"
        return {"arquivo": self.mod.arquivo, "status": status, "severidade": sev,
                "fonte": {"tipo": r.tipo, "linha": r.linha, "descricao": r.origem},
                "sink": {"tipo": tipo, "linha": c.lineno, "descricao": DESC_SINK[tipo], "codigo": _trecho(c)},
                "parcial": r.parcial, "explicacao": expl}


def _trecho(no):
    try:
        s = ast.unparse(no)
    except Exception:
        s = ""
    return s if len(s) <= 140 else s[:137] + "..."


POLITICA_PADRAO = {"brokers_publicos": ["broker.hivemq.com", "test.mosquitto.org", "broker.emqx.io", "mqtt.eclipseprojects.io"]}


def analisar_arquivo(caminho, nome_exibido=None, motor=None, politica=None):
    try:
        with open(caminho, encoding="utf-8") as f:
            fonte = f.read()
        arvore = ast.parse(fonte)
    except (SyntaxError, UnicodeDecodeError, OSError):
        return [], []
    mod = Modulo(arvore, nome_exibido or caminho, politica or POLITICA_PADRAO, motor or Motor())
    fluxos, sanit = mod.analisar()
    fluxos.sort(key=lambda f: (-SEV_ORDEM[f["severidade"]], f["sink"]["linha"]))
    return fluxos, sorted(sanit, key=lambda s: s["linha"])


def analisar_pasta(raiz, motor=None, ignorar=("tests", "test", ".git", "node_modules", "__pycache__", "venv", ".venv")):
    motor = motor or Motor()
    fluxos, sanit = [], []
    for d, ds, fs in os.walk(raiz):
        ds[:] = [x for x in ds if x not in ignorar]
        for f in sorted(fs):
            if f.endswith(".py"):
                p = os.path.join(d, f)
                a, b = analisar_arquivo(p, os.path.relpath(p, raiz).replace("\\", "/"), motor)
                fluxos += a
                sanit += b
    return fluxos, sanit
