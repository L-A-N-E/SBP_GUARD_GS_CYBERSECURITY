"""Motor de parsing PII do SBP Guard.

Le texto, JSON, .env e codigo-fonte e encontra dados pessoais (LGPD) com regras
declarativas (regras_pii.json) + validadores (digito do CPF, do Cartao SUS, Luhn).
Nada aqui guarda ou devolve o valor bruto: cada achado traz so a mascara e uma
impressao digital curta (SHA-256), para nunca vazar o que esta sendo protegido.
"""
import hashlib
import json
import math
import os
import re
from dataclasses import dataclass, asdict, field

PASTA = os.path.dirname(os.path.abspath(__file__))
SEV_ORDEM = {"baixa": 0, "media": 1, "alta": 2, "critica": 3}

# troca 1 caractere por 1 caractere: as posicoes do texto normalizado batem com as do original
_ACENTOS = str.maketrans("áàâãäéèêëíìîïóòôõöúùûüçÁÀÂÃÄÉÈÊËÍÌÎÏÓÒÔÕÖÚÙÛÜÇ",
                         "aaaaaeeeeiiiiooooouuuucAAAAAEEEEIIIIOOOOOUUUUC")


def normalizar(texto):
    return texto.translate(_ACENTOS)


def impressao(valor):
    return hashlib.sha256(str(valor).encode("utf-8")).hexdigest()[:8]


# ---------------------------------------------------------------- validadores
def valida_cpf(v):
    d = re.sub(r"\D", "", v)
    if len(d) != 11 or d == d[0] * 11:
        return False
    for n in (9, 10):
        soma = sum(int(d[i]) * (n + 1 - i) for i in range(n))
        dv = (soma * 10) % 11 % 10
        if dv != int(d[n]):
            return False
    return True


def valida_cns(v):
    d = re.sub(r"\D", "", v)
    if len(d) != 15 or d[0] not in "12789" or d == d[0] * 15:
        return False
    return sum(int(d[i]) * (15 - i) for i in range(15)) % 11 == 0


def valida_luhn(v):
    d = re.sub(r"\D", "", v)
    if len(d) < 13 or d == d[0] * len(d):
        return False
    total = 0
    for i, c in enumerate(reversed(d)):
        n = int(c)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def entropia(s):
    if not s:
        return 0.0
    return -sum(s.count(c) / len(s) * math.log2(s.count(c) / len(s)) for c in set(s))


class Motor:
    """Carrega as regras e analisa conteudo. Use Motor() uma vez e reaproveite."""

    def __init__(self, caminho_regras=None):
        with open(caminho_regras or os.path.join(PASTA, "regras_pii.json"), encoding="utf-8") as f:
            cfg = json.load(f)
        self.placeholders = [p.lower() for p in cfg.get("placeholders", [])]
        self.regras = []
        for r in cfg["regras"]:
            r = dict(r)
            r["_re"] = re.compile(r["padrao"])
            r["_ign"] = [re.compile(x, re.I) for x in r.get("ignorar", [])]
            self.regras.append(r)
        self.chaves = [dict(c, _re=re.compile(c["padrao"], re.I)) for c in cfg["chaves"]]
        self._val = {"cpf": valida_cpf, "cns": valida_cns, "luhn": valida_luhn,
                     "segredo": self.segredo_plausivel, "nenhum": lambda v: True}

    # um "segredo" de verdade: nao e placeholder nem nome de variavel
    def segredo_plausivel(self, v):
        v = v.strip().strip("\"'")
        b = v.lower()
        if len(v) < 6 or any(p in b for p in self.placeholders):
            return False
        if re.fullmatch(r"[A-Za-z_][A-Za-z_.]*(\(\))?", v):    # token=token, senha=self.senha
            return False
        if re.fullmatch(r"[a-z]+(-[a-z]+)+", v):               # palavras-com-hifen, ex.: token-recusado
            return False
        return bool(re.search(r"\d", v)) or entropia(v) >= 3.3

    def regra_de_chave(self, chave):
        k = normalizar(str(chave)).lower().strip()
        for c in self.chaves:
            if c["_re"].search(k):
                return c
        return None

    # -------------------------------------------------------- texto livre
    def analisar_texto(self, texto, origem="<texto>", linha_base=1, chave=None):
        if not isinstance(texto, str) or not texto:
            return []
        norm = normalizar(texto)
        baixo = norm.lower()
        achados, spans = [], []
        for r in self.regras:
            for m in r["_re"].finditer(norm):
                g = 1 if m.groups() else 0
                ini, fim = m.span(g)
                valor = texto[ini:fim]
                if any(i.search(valor) for i in r["_ign"]):
                    continue
                val = self._val.get(r.get("validador", "nenhum"))
                if not val(valor):
                    continue
                if not self._contexto_ok(r, baixo, ini, fim, chave, norm):
                    continue
                spans.append((ini, fim))
                achados.append(self._novo(r, valor, texto, ini, origem, linha_base, "texto"))
        return _sem_sobreposicao(achados)

    def _contexto_ok(self, r, baixo, ini, fim, chave, norm):
        ctx = r.get("contexto")
        if not ctx:
            return True
        if chave and self.regra_de_chave(chave) and self.regra_de_chave(chave)["categoria"] == r["categoria"]:
            return True
        j = ctx.get("janela", 40)
        trecho = baixo[max(0, ini - j): fim + j]
        if any(re.search(r"\b" + re.escape(p) + r"\b", trecho) for p in ctx["palavras"]):
            return True
        if ctx.get("aceita_identificador_proximo"):
            viz = norm[max(0, ini - 160): fim + 160]
            for rid in ("cpf", "cartao_sus", "email", "telefone"):
                rr = next(x for x in self.regras if x["id"] == rid)
                for m in rr["_re"].finditer(viz):
                    v = m.group(1)
                    if self._val.get(rr.get("validador", "nenhum"))(v):
                        return True
        return not ctx.get("obrigatorio", False)

    def _novo(self, r, valor, texto, ini, origem, linha_base, via):
        linha = linha_base + texto.count("\n", 0, ini)
        col = ini - (texto.rfind("\n", 0, ini) + 1) + 1
        return Achado(regra=r["id"], nome=r["nome"], categoria=r["categoria"], lgpd=r["lgpd"],
                      severidade=r["severidade"], arquivo=origem, linha=linha, coluna=col,
                      mascara=mascarar(valor, r["categoria"], r["id"]), impressao=impressao(valor),
                      tamanho=len(valor), via=via, _valor=valor)

    # -------------------------------------------------------- estruturado
    def analisar_json(self, obj, origem="<json>", linha=1, caminho="$"):
        achados = []
        if isinstance(obj, dict):
            irmaos = [self.regra_de_chave(k) for k in obj]
            tem_pessoal = sum(1 for c in irmaos if c and c["id"] != "campo_nome") > 0
            for k, v in obj.items():
                cam = "%s.%s" % (caminho, k)
                c = self.regra_de_chave(k)
                if c and c.get("exige_irmao_pessoal") and not tem_pessoal:
                    c = None
                if c and v not in (None, "", [], {}) and not isinstance(v, (dict, list, bool)):
                    sv = str(v)
                    val = self._val.get(c.get("validador", "nenhum"))
                    if val(sv):
                        a = Achado(regra=c["id"], nome=c["nome"], categoria=c["categoria"], lgpd=c["lgpd"],
                                   severidade=c["severidade"], arquivo=origem, linha=linha, coluna=1,
                                   mascara=mascarar(sv, c["categoria"], c["id"]), impressao=impressao(sv),
                                   tamanho=len(sv), via="campo " + cam, _valor=sv)
                        achados.append(a)
                achados += self.analisar_json(v, origem, linha, cam) if isinstance(v, (dict, list)) else \
                    self.analisar_texto(str(v), origem, linha, chave=k) if isinstance(v, (str, int)) and not isinstance(v, bool) else []
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                achados += self.analisar_json(v, origem, linha, "%s[%d]" % (caminho, i))
        elif isinstance(obj, str):
            achados += self.analisar_texto(obj, origem, linha)
        return _dedup(achados)

    def analisar_env(self, texto, origem, protegido_git=False):
        achados = []
        for n, linha in enumerate(texto.splitlines(), 1):
            m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", linha)
            if not m:
                continue
            k, v = m.group(1), m.group(2).strip().strip("\"'")
            c = self.regra_de_chave(k)
            if c and c["categoria"] == "credencial" and self.segredo_plausivel(v):
                a = Achado(regra="segredo_env", nome="Credencial em arquivo .env", categoria="credencial",
                           lgpd=c["lgpd"], severidade="media" if protegido_git else "critica", arquivo=origem,
                           linha=n, coluna=1, mascara=mascarar(v, "credencial"), impressao=impressao(v),
                           tamanho=len(v), via="variavel " + k, _valor=v,
                           nota="arquivo fora do git (.gitignore) — risco se for copiado ou enviado" if protegido_git
                           else "arquivo .env NAO esta no .gitignore — pode ir para o repositorio")
                achados.append(a)
            else:
                achados += self.analisar_texto(linha, origem, n)
        return achados

    def analisar_arquivo(self, caminho, nome_exibido=None, protegido_git=False):
        nome = nome_exibido or caminho
        try:
            if os.path.getsize(caminho) > 8_000_000:
                return []
            with open(caminho, "rb") as f:
                bruto = f.read()
        except OSError:
            return []
        if b"\x00" in bruto[:4096]:
            return []
        texto = bruto.decode("utf-8", errors="replace")
        base = os.path.basename(caminho).lower()
        if base == ".env" or base.endswith(".env"):
            return self.analisar_env(texto, nome, protegido_git)
        if base.endswith(".json"):
            try:
                return self.analisar_json(json.loads(texto), nome)
            except ValueError:
                pass
        if base.endswith(".jsonl"):
            out = []
            for n, l in enumerate(texto.splitlines(), 1):
                for parte in l.split("\t"):
                    try:
                        out += self.analisar_json(json.loads(parte), nome, n)
                    except ValueError:
                        out += self.analisar_texto(parte, nome, n)
            return _dedup(out)
        return self.analisar_texto(texto, nome)


@dataclass
class Achado:
    regra: str
    nome: str
    categoria: str
    lgpd: str
    severidade: str
    arquivo: str
    linha: int
    coluna: int
    mascara: str
    impressao: str
    tamanho: int
    via: str
    nota: str = ""
    _valor: str = field(default="", repr=False)

    def publico(self):
        """Versao segura para relatorio/IA/painel: sem o valor bruto."""
        d = asdict(self)
        d.pop("_valor")
        return d


def mascarar(valor, categoria="", regra=""):
    v = str(valor)
    if categoria == "credencial":
        return "[segredo oculto · %d caracteres · #%s]" % (len(v), impressao(v))
    if regra in ("cpf", "campo_cpf"):
        d = re.sub(r"\D", "", v)
        if len(d) == 11:                       # padrao usado em documentos publicos: ***.456.***-00
            return "***.%s.***-%s" % (d[3:6], d[9:])
        return "*" * len(v)
    if regra == "rg":
        return "**.***.***-*"
    if regra in ("email",) or "@" in v:
        u, _, d = v.partition("@")
        return (u[:1] + "***@***." + d.rsplit(".", 1)[-1]) if d else "***"
    if regra in ("telefone",):
        return "(**) *****-" + re.sub(r"\D", "", v)[-2:].rjust(4, "*")
    if regra in ("nome_rotulado", "campo_nome"):
        return " ".join(p[:1] + "***" for p in v.split())
    if categoria == "saude":
        return "[dado de saúde oculto]"
    return "*" * min(len(v), 12)


def _sem_sobreposicao(achados):
    achados.sort(key=lambda a: (a.linha, a.coluna, -SEV_ORDEM[a.severidade]))
    out = []
    for a in achados:
        if out and out[-1].linha == a.linha and a.coluna < out[-1].coluna + out[-1].tamanho:
            if SEV_ORDEM[a.severidade] > SEV_ORDEM[out[-1].severidade]:
                out[-1] = a
            continue
        out.append(a)
    return out


def _dedup(achados):
    vistos, out = set(), []
    for a in achados:
        k = (a.arquivo, a.linha, a.impressao, a.categoria)
        if k not in vistos:
            vistos.add(k)
            out.append(a)
    return out


def mascarar_texto(texto, motor):
    """Devolve o texto com todo dado pessoal encontrado trocado pela mascara."""
    achs = motor.analisar_texto(texto)
    for a in sorted(achs, key=lambda a: -len(a._valor)):
        texto = texto.replace(a._valor, a.mascara)
    return texto


def mascarar_dado(obj, motor):
    """Mascara recursivamente dicionarios/listas/strings (usado pelo guardiao)."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            c = motor.regra_de_chave(k)
            if c and isinstance(v, (str, int)) and not isinstance(v, bool) and str(v):
                out[k] = mascarar(str(v), c["categoria"], c["id"])
            else:
                out[k] = mascarar_dado(v, motor)
        return out
    if isinstance(obj, list):
        return [mascarar_dado(v, motor) for v in obj]
    if isinstance(obj, str):
        return mascarar_texto(obj, motor)
    return obj
