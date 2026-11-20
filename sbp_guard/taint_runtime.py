"""Taint em tempo de execucao: o "Guardiao" do SBP.

Duas defesas juntas, porque cada uma sozinha falha:
  1) Rotulo: valores vindos do cidadao sao marcados com Sensivel(...). Se um valor
     marcado chega numa saida insegura, e bloqueado.
  2) Re-leitura do conteudo: f-string, json.dumps e .format() criam strings novas
     e PERDEM o rotulo. Por isso toda saida tambem e lida pelo motor PII; se ainda
     houver CPF, saude, senha... no texto, bloqueia do mesmo jeito.
Nada de valor bruto vai para o registro de auditoria: so mascara e impressao digital.
"""
import json
import time

from .pii import Motor, mascarar_dado, impressao


class Sensivel(str):
    """str que lembra de onde veio (rotulo). Operacoes de str devolvem str comum."""

    def __new__(cls, valor, rotulo="pessoal"):
        obj = super().__new__(cls, valor)
        obj.rotulo = rotulo
        return obj


def marcar(dados, rotulos):
    """Marca campos de um dict vindo do cidadao. rotulos: {"cpf": "pessoal", "condicao": "saude"}."""
    out = dict(dados)
    for k, r in rotulos.items():
        if isinstance(out.get(k), str):
            out[k] = Sensivel(out[k], r)
    return out


def interceptar_entrada(dados, motor=None):
    """Middleware de ENTRADA: varre o JSON que chegou (formulario/API) e marca como PII
    todo campo em que o motor achar dado sensivel — pela chave (cpf, documento, condicao...)
    ou pelo conteudo (um CPF escrito num campo 'observacao', por exemplo).
    Devolve (dados_marcados, relatorio_com_mascaras). Nenhum campo precisa ser declarado a mao."""
    motor = motor or Motor()
    marcado, relatorio = {}, []
    for k, v in dados.items():
        if not isinstance(v, (str, int)) or isinstance(v, bool):
            marcado[k] = v
            continue
        sv = str(v)
        c = motor.regra_de_chave(k)
        if c and c.get("exige_irmao_pessoal"):
            c = c if any(motor.regra_de_chave(x) and x != k for x in dados) else None
        achados = motor.analisar_texto(sv, "<entrada>", chave=k)
        cats = ({c["categoria"]} if c else set()) | {a.categoria for a in achados}
        if not cats:
            marcado[k] = v
            continue
        rotulo = "saude" if "saude" in cats else "credencial" if "credencial" in cats else "pessoal"
        marcado[k] = Sensivel(sv, rotulo)
        from .pii import mascarar
        regra = (c or {}).get("id") or (achados[0].regra if achados else "")
        relatorio.append({"campo": k, "rotulo": rotulo, "categorias": sorted(cats),
                          "mascara": achados[0].mascara if achados else mascarar(sv, (c or {}).get("categoria", ""), regra)})
    return marcado, relatorio


class VazamentoBloqueado(Exception):
    def __init__(self, evento):
        super().__init__("vazamento bloqueado para %s (%s)" % (evento["destino"], ", ".join(evento["categorias"])))
        self.evento = evento


class Destino:
    def __init__(self, nome, seguro, descricao):
        self.nome, self.seguro, self.descricao = nome, seguro, descricao


DESTINOS = {
    "mqtt_publico": Destino("mqtt_publico", False, "broker MQTT público (broker.hivemq.com)"),
    "log": Destino("log", False, "log da aplicação"),
    "llm": Destino("llm", False, "modelo de IA"),
    "arquivo_texto": Destino("arquivo_texto", False, "arquivo de texto sem criptografia"),
    "painel_publico": Destino("painel_publico", False, "Ponto Virtual (painel aberto ao público)"),
    "tela_app": Destino("tela_app", False, "resposta HTTP sem autenticação que aparece na tela do app"),
    "cofre": Destino("cofre", True, "armazenamento criptografado com acesso controlado"),
    "operador_autenticado": Destino("operador_autenticado", True, "canal autenticado do motorista/operador (TLS)"),
}


def _rotulos(obj, acc):
    if isinstance(obj, Sensivel):
        acc.add(obj.rotulo)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            _rotulos(k, acc)
            _rotulos(v, acc)
    elif isinstance(obj, (list, tuple, set)):
        for v in obj:
            _rotulos(v, acc)
    return acc


class Guardiao:
    """modo: 'bloquear' (levanta VazamentoBloqueado), 'mascarar' (deixa sair mascarado)
    ou 'monitorar' (so registra — usado para medir o 'antes')."""

    def __init__(self, modo="bloquear", motor=None):
        self.modo = modo
        self.motor = motor or Motor()
        self.eventos = []

    def verificar(self, dado, destino, contexto=""):
        d = DESTINOS[destino] if isinstance(destino, str) else destino
        rot = _rotulos(dado, set())
        if isinstance(dado, (dict, list)):
            achados = self.motor.analisar_json(dado, "<saida>")
        else:
            achados = self.motor.analisar_texto(str(dado), "<saida>")
        cats = sorted({a.categoria for a in achados} | {"saude" if r == "saude" else "credencial" if r == "credencial" else "identificador" for r in rot})
        if not cats:
            return dado
        evento = {"quando": time.strftime("%H:%M:%S"), "destino": d.nome, "destino_desc": d.descricao,
                  "contexto": contexto, "categorias": cats,
                  "detectado_por": "rótulo + conteúdo" if rot and achados else "rótulo" if rot else "conteúdo",
                  "itens": [{"tipo": a.nome, "mascara": a.mascara, "impressao": a.impressao} for a in achados][:8],
                  "assinatura": impressao(json.dumps(dado, ensure_ascii=False, default=str, sort_keys=True))}
        if d.seguro:
            evento["acao"] = "permitido (destino seguro)"
            self.eventos.append(evento)
            return dado
        if self.modo == "bloquear":
            evento["acao"] = "bloqueado"
            self.eventos.append(evento)
            raise VazamentoBloqueado(evento)
        if self.modo == "mascarar":
            evento["acao"] = "mascarado"
            self.eventos.append(evento)
            return mascarar_dado(dado, self.motor) if not isinstance(dado, str) else mascarar_dado(str(dado), self.motor)
        evento["acao"] = "vazou"
        self.eventos.append(evento)
        return dado

    def resumo(self):
        r = {"bloqueado": 0, "mascarado": 0, "vazou": 0, "permitido (destino seguro)": 0}
        for e in self.eventos:
            r[e["acao"]] = r.get(e["acao"], 0) + 1
        return r


# ----------------------------------------------------------------- saidas protegidas
class BrokerProtegido:
    """Envolve um cliente MQTT: todo publish passa pelo guardiao antes de sair."""

    def __init__(self, cliente, guardiao, destino="mqtt_publico"):
        self.cliente, self.g, self.destino = cliente, guardiao, destino

    def publish(self, topico, payload=None, *a, **k):
        try:
            dado = json.loads(payload) if isinstance(payload, str) and payload[:1] in "{[" else payload
        except ValueError:
            dado = payload
        self.g.verificar(dado if isinstance(dado, (dict, list)) else payload, self.destino, "publish " + topico)
        return self.cliente.publish(topico, payload, *a, **k)


class LogProtegido:
    def __init__(self, logger, guardiao):
        self.logger, self.g = logger, guardiao

    def _passa(self, nivel, msg, *args):
        texto = (msg % args) if args else str(msg)
        texto = self.g.verificar(texto, "log", "log." + nivel)
        getattr(self.logger, nivel)(texto)

    def info(self, msg, *a):
        self._passa("info", msg, *a)

    def warning(self, msg, *a):
        self._passa("warning", msg, *a)

    def error(self, msg, *a):
        self._passa("error", msg, *a)


class IAProtegida:
    def __init__(self, funcao_ia, guardiao):
        self.f, self.g = funcao_ia, guardiao

    def __call__(self, texto):
        self.g.verificar(texto, "llm", "prompt para IA")
        return self.f(texto)
