"""Mede a robustez do motor PII com um corpus rotulado (precisao e recall por regra).

Positivos: dados no formato real (com e sem pontuacao, dentro de JSON, de log, de
codigo). Negativos: o que o SBP manda de verdade (telemetria MQTT, codigos de linha,
ids de parada, coordenadas) + armadilhas (CPF com digito errado, placeholders).
Os documentos sao gerados aqui, com dados ficticios.
"""
import json
import random

from .pii import Motor, valida_cns


def _cpf(rng, mascara=True):
    n = [rng.randint(0, 9) for _ in range(9)]
    for k in (10, 11):
        n.append(sum(d * (k - i) for i, d in enumerate(n)) * 10 % 11 % 10)
    d = "".join(map(str, n))
    return "%s.%s.%s-%s" % (d[:3], d[3:6], d[6:9], d[9:]) if mascara else d


def _cns(rng):
    while True:
        pis = "".join(str(rng.randint(0, 9)) for _ in range(11))
        pis = str(rng.choice([1, 2])) + pis[1:]
        soma = sum(int(pis[i]) * (15 - i) for i in range(11))
        dv = 11 - soma % 11
        if dv == 11:
            dv = 0
        if dv == 10:
            soma += 2
            dv = 11 - soma % 11
            c = pis + "001" + str(dv)
        else:
            c = pis + "000" + str(dv)
        if valida_cns(c):
            return "%s %s %s %s" % (c[:3], c[3:7], c[7:11], c[11:])


def _luhn(rng):
    n = [4] + [rng.randint(0, 9) for _ in range(14)]
    s = 0
    for i, d in enumerate(reversed(n)):
        x = d * 2 if i % 2 == 0 else d
        s += x - 9 if x > 9 else x
    n.append((10 - s % 10) % 10)
    d = "".join(map(str, n))
    return " ".join(d[i:i + 4] for i in range(0, 16, 4))


def corpus(semente=7):
    rng = random.Random(semente)
    pos, neg = [], []
    for _ in range(12):
        c = _cpf(rng)
        pos += [(f"CPF do passageiro: {c}", {"cpf"}), (f'{{"cpf": "{_cpf(rng, False)}", "ponto": "3703094"}}', {"cpf"}),
                (f"log: pedido aceito cpf={c} linha=5757-51", {"cpf"})]
        cpf_errado = c[:-1] + str((int(c[-1]) + 1) % 10)
        neg.append((f"CPF {cpf_errado} digitado errado", set()))
        pos.append((f"Cartão SUS {_cns(rng)}", {"cartao_sus"}))
        pos.append((f"Paciente com diabetes, CID E11.9, retorno em 30 dias", {"condicao_saude", "cid10"}))
        pos.append((f"Passageira: Ana Souza — cadeirante — CPF {_cpf(rng)}", {"nome_rotulado", "condicao_saude", "cpf"}))
        pos.append((f"contato: joana.ribeiro{rng.randint(1, 99)}@gmail.com tel (11) 9{rng.randint(1000, 9999)}-{rng.randint(1000, 9999)}", {"email", "telefone"}))
        pos.append((f'senha = "Tr0c4r@{rng.randint(100, 999)}x"', {"senha_atribuida"}))
        pos.append((f"Authorization: Bearer eyJhbGciOi{rng.randint(10**9, 10**10)}abcDEF", {"bearer"}))
        pos.append((f"cartao 4{_luhn(rng)[1:]}", {"cartao_credito"}))
        alfa = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        pos.append(("deploy usa AKIA" + "".join(rng.choice(alfa) for _ in range(16)) + " no CI", {"chave_conhecida"}))
        pos.append((f"WhatsApp +55 11 9{rng.randint(1000, 9999)} {rng.randint(1000, 9999)} do responsável", {"telefone"}))
        pos.append((f"data de nascimento: {rng.randint(10, 28)}/0{rng.randint(1, 9)}/19{rng.randint(50, 99)}", {"data_nascimento"}))
    neg += [
        ('{"online":true,"totem":"sbp-0001","ponto":"2203206","nome":"Avenida Cupece, 4734","final":false,"lat":-23.675470,"lon":-46.642506}', set()),
        ('{"tipo":"presenca","ponto":"3703094","hora":7,"relogio":"07:30"}', set()),
        ('{"n":"607C-10","d":"Jardim Miriam","g":0,"eta":[0,5,10]}', set()),
        ('Ponto Avenida Cupece, 4734. Próximos ônibus: linha 5123-10, Jardim Miriam, chegando agora', set()),
        ('{"ponto":"3703094","hora":18,"presencas":[0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,1,1,0,0,0,0,0]}', set()),
        ("18,6 milhões de pessoas com deficiência no Brasil (IBGE 2022)", set()),
        ("O botão verde ajuda quem tem deficiência visual a ouvir a previsão", set()),
        ("self.token = token", set()), ("token = os.environ.get('SPTRANS_TOKEN')", set()),
        ("SPTRANS_TOKEN=seu_token_aqui", set()), ("password: ${DB_PASSWORD}", set()),
        ("versão 1.2.3 build 20261117 hash a1b2c3d4", set()), ("lat -23.5505199, lon -46.6333094", set()),
        ("parada 18001234567 é um id longo de parada", set()), ("nome: Terminal Bandeira", set()),
        ("protocolo 2026111712345 aberto às 10:22", set()), ("o CID de rede 10.0.0.0/8 é privado", set()),
        ("ônibus 11 99999 9999 de frota", set()), ("token-de-teste para o servidor falso", set()),
    ]
    return pos, neg


def avaliar(motor=None):
    motor = motor or Motor()
    pos, neg = corpus()
    regras = sorted({r["id"] for r in motor.regras})
    m = {r: {"vp": 0, "fp": 0, "fn": 0} for r in regras}
    erros = []
    for texto, esperado in pos + neg:
        achado = {a.regra for a in motor.analisar_texto(texto)}
        for r in regras:
            if r in achado and r in esperado:
                m[r]["vp"] += 1
            elif r in achado:
                m[r]["fp"] += 1
                erros.append({"tipo": "falso positivo", "regra": r, "amostra": motor_mascara(motor, texto)})
            elif r in esperado:
                m[r]["fn"] += 1
                erros.append({"tipo": "falso negativo", "regra": r, "amostra": motor_mascara(motor, texto)})
    tot = {"vp": sum(x["vp"] for x in m.values()), "fp": sum(x["fp"] for x in m.values()), "fn": sum(x["fn"] for x in m.values())}
    for x in list(m.values()) + [tot]:
        x["precisao"] = round(x["vp"] / (x["vp"] + x["fp"]), 3) if x["vp"] + x["fp"] else None
        x["recall"] = round(x["vp"] / (x["vp"] + x["fn"]), 3) if x["vp"] + x["fn"] else None
    return {"amostras_positivas": len(pos), "amostras_negativas": len(neg), "por_regra": m, "geral": tot, "erros": erros[:20]}


def motor_mascara(motor, texto):
    from .pii import mascarar_texto
    return mascarar_texto(texto, motor)


if __name__ == "__main__":
    print(json.dumps(avaliar()["geral"], indent=1))
