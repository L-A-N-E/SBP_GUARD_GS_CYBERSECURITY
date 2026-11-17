window.RELATORIO = {
 "gerado_em": "17/11/2026 19:58:19",
 "duracao_s": 4.7,
 "regras": {
  "texto": 12,
  "campos": 8
 },
 "metricas_pii": {
  "amostras_positivas": 156,
  "amostras_negativas": 31,
  "por_regra": {
   "bearer": {
    "vp": 12,
    "fp": 0,
    "fn": 0,
    "precisao": 1.0,
    "recall": 1.0
   },
   "cartao_credito": {
    "vp": 12,
    "fp": 0,
    "fn": 0,
    "precisao": 1.0,
    "recall": 1.0
   },
   "cartao_sus": {
    "vp": 12,
    "fp": 0,
    "fn": 0,
    "precisao": 1.0,
    "recall": 1.0
   },
   "chave_conhecida": {
    "vp": 12,
    "fp": 0,
    "fn": 0,
    "precisao": 1.0,
    "recall": 1.0
   },
   "cid10": {
    "vp": 12,
    "fp": 0,
    "fn": 0,
    "precisao": 1.0,
    "recall": 1.0
   },
   "condicao_saude": {
    "vp": 24,
    "fp": 0,
    "fn": 0,
    "precisao": 1.0,
    "recall": 1.0
   },
   "cpf": {
    "vp": 48,
    "fp": 0,
    "fn": 0,
    "precisao": 1.0,
    "recall": 1.0
   },
   "data_nascimento": {
    "vp": 12,
    "fp": 0,
    "fn": 0,
    "precisao": 1.0,
    "recall": 1.0
   },
   "email": {
    "vp": 12,
    "fp": 0,
    "fn": 0,
    "precisao": 1.0,
    "recall": 1.0
   },
   "nome_rotulado": {
    "vp": 12,
    "fp": 0,
    "fn": 0,
    "precisao": 1.0,
    "recall": 1.0
   },
   "senha_atribuida": {
    "vp": 12,
    "fp": 0,
    "fn": 0,
    "precisao": 1.0,
    "recall": 1.0
   },
   "telefone": {
    "vp": 24,
    "fp": 1,
    "fn": 0,
    "precisao": 0.96,
    "recall": 1.0
   }
  },
  "geral": {
   "vp": 204,
   "fp": 1,
   "fn": 0,
   "precisao": 0.995,
   "recall": 1.0
  },
  "erros": [
   {
    "tipo": "falso positivo",
    "regra": "telefone",
    "amostra": "ônibus (**) *****-**99 de frota"
   }
  ]
 },
 "alvos": [
  {
   "id": "sbp",
   "nome": "SBP — código real do totem e do servidor",
   "caminho": "GS2026_IOT_S.P.B",
   "arquivos": 28,
   "megabytes": 4.6,
   "pii": [
    {
     "regra": "segredo_env",
     "nome": "Credencial em arquivo .env",
     "categoria": "credencial",
     "lgpd": "Art. 46 — segurança dos dados (credencial de acesso)",
     "severidade": "media",
     "arquivo": ".env",
     "linha": 1,
     "coluna": 1,
     "mascara": "[segredo oculto · 64 caracteres · #a2dc9f61]",
     "impressao": "a2dc9f61",
     "tamanho": 64,
     "via": "variavel SPTRANS_TOKEN",
     "nota": "arquivo fora do git (.gitignore) — risco se for copiado ou enviado",
     "id": "4ea35331e6"
    }
   ],
   "fluxos": [
    {
     "arquivo": "servidor_sbp.py",
     "status": "VAZAMENTO",
     "severidade": "critica",
     "fonte": {
      "tipo": "credencial",
      "linha": 68,
      "descricao": "parâmetro 'token'"
     },
     "sink": {
      "tipo": "rede_http",
      "linha": 104,
      "descricao": "requisição de rede que pode sair em HTTP sem criptografia",
      "codigo": "urllib.request.Request(base + '/Login/Autenticar?token=' + urllib.parse.quote(self.token), method='POST', data=b'')"
     },
     "parcial": false,
     "explicacao": "Valor de credencial/segredo chega em requisição de rede que pode sair em HTTP sem criptografia: a lista de URLs inclui http:// — o dado trafega sem criptografia se o HTTPS falhar"
    },
    {
     "arquivo": "servidor_sbp.py",
     "status": "VAZAMENTO",
     "severidade": "critica",
     "fonte": {
      "tipo": "credencial",
      "linha": 68,
      "descricao": "parâmetro 'token'"
     },
     "sink": {
      "tipo": "rede_http",
      "linha": 126,
      "descricao": "requisição de rede que pode sair em HTTP sem criptografia",
      "codigo": "urllib.request.Request(base + '/Login/Autenticar?token=' + urllib.parse.quote(self.token), method='POST', data=b'')"
     },
     "parcial": false,
     "explicacao": "Valor de credencial/segredo chega em requisição de rede que pode sair em HTTP sem criptografia: a lista de URLs inclui http:// — o dado trafega sem criptografia se o HTTPS falhar"
    },
    {
     "arquivo": "servidor_sbp.py",
     "status": "VAZAMENTO",
     "severidade": "baixa",
     "fonte": {
      "tipo": "credencial",
      "linha": 68,
      "descricao": "parâmetro 'token'"
     },
     "sink": {
      "tipo": "console",
      "linha": 124,
      "descricao": "saída no console/terminal (vai parar em logs)",
      "codigo": "print('token: %s' % ('...%s (%d caracteres)' % (self.token[-4:], len(self.token)) if self.token else 'NAO ENCONTRADO (.env)'))"
     },
     "parcial": true,
     "explicacao": "Parte de credencial/segredo chega em saída no console/terminal (vai parar em logs)"
    },
    {
     "arquivo": "servidor_sbp.py",
     "status": "VAZAMENTO",
     "severidade": "baixa",
     "fonte": {
      "tipo": "credencial",
      "linha": 54,
      "descricao": "variável de ambiente SPTRANS_TOKEN"
     },
     "sink": {
      "tipo": "console",
      "linha": 314,
      "descricao": "saída no console/terminal (vai parar em logs)",
      "codigo": "print('[olhovivo]', 'token carregado (...%s)' % tok[-4:] if tok else 'sem token: rodando so com a grade GTFS')"
     },
     "parcial": true,
     "explicacao": "Parte de credencial/segredo chega em saída no console/terminal (vai parar em logs)"
    },
    {
     "arquivo": "servidor_sbp.py",
     "status": "VAZAMENTO",
     "severidade": "baixa",
     "fonte": {
      "tipo": "credencial",
      "linha": 57,
      "descricao": "leitura do arquivo .env"
     },
     "sink": {
      "tipo": "console",
      "linha": 314,
      "descricao": "saída no console/terminal (vai parar em logs)",
      "codigo": "print('[olhovivo]', 'token carregado (...%s)' % tok[-4:] if tok else 'sem token: rodando so com a grade GTFS')"
     },
     "parcial": true,
     "explicacao": "Parte de credencial/segredo chega em saída no console/terminal (vai parar em logs)"
    }
   ],
   "fluxos_agrupados": [
    {
     "arquivo": "servidor_sbp.py",
     "status": "VAZAMENTO",
     "severidade": "critica",
     "fonte": {
      "tipo": "credencial",
      "linha": 68,
      "descricao": "parâmetro 'token'"
     },
     "sink": {
      "tipo": "rede_http",
      "linha": 104,
      "descricao": "requisição de rede que pode sair em HTTP sem criptografia",
      "codigo": "urllib.request.Request(base + '/Login/Autenticar?token=' + urllib.parse.quote(self.token), method='POST', data=b'')"
     },
     "parcial": false,
     "explicacao": "Valor de credencial/segredo chega em requisição de rede que pode sair em HTTP sem criptografia: a lista de URLs inclui http:// — o dado trafega sem criptografia se o HTTPS falhar",
     "id": "b3b7adeab4",
     "dados": [
      "credencial"
     ],
     "fontes": [
      "L68 · parâmetro 'token'"
     ]
    },
    {
     "arquivo": "servidor_sbp.py",
     "status": "VAZAMENTO",
     "severidade": "critica",
     "fonte": {
      "tipo": "credencial",
      "linha": 68,
      "descricao": "parâmetro 'token'"
     },
     "sink": {
      "tipo": "rede_http",
      "linha": 126,
      "descricao": "requisição de rede que pode sair em HTTP sem criptografia",
      "codigo": "urllib.request.Request(base + '/Login/Autenticar?token=' + urllib.parse.quote(self.token), method='POST', data=b'')"
     },
     "parcial": false,
     "explicacao": "Valor de credencial/segredo chega em requisição de rede que pode sair em HTTP sem criptografia: a lista de URLs inclui http:// — o dado trafega sem criptografia se o HTTPS falhar",
     "id": "c2d340d35f",
     "dados": [
      "credencial"
     ],
     "fontes": [
      "L68 · parâmetro 'token'"
     ]
    },
    {
     "arquivo": "servidor_sbp.py",
     "status": "VAZAMENTO",
     "severidade": "baixa",
     "fonte": {
      "tipo": "credencial",
      "linha": 68,
      "descricao": "parâmetro 'token'"
     },
     "sink": {
      "tipo": "console",
      "linha": 124,
      "descricao": "saída no console/terminal (vai parar em logs)",
      "codigo": "print('token: %s' % ('...%s (%d caracteres)' % (self.token[-4:], len(self.token)) if self.token else 'NAO ENCONTRADO (.env)'))"
     },
     "parcial": true,
     "explicacao": "Parte de credencial/segredo chega em saída no console/terminal (vai parar em logs)",
     "id": "137bdbeb61",
     "dados": [
      "credencial"
     ],
     "fontes": [
      "L68 · parâmetro 'token'"
     ]
    },
    {
     "arquivo": "servidor_sbp.py",
     "status": "VAZAMENTO",
     "severidade": "baixa",
     "fonte": {
      "tipo": "credencial",
      "linha": 54,
      "descricao": "variável de ambiente SPTRANS_TOKEN"
     },
     "sink": {
      "tipo": "console",
      "linha": 314,
      "descricao": "saída no console/terminal (vai parar em logs)",
      "codigo": "print('[olhovivo]', 'token carregado (...%s)' % tok[-4:] if tok else 'sem token: rodando so com a grade GTFS')"
     },
     "parcial": true,
     "explicacao": "Parte de credencial/segredo chega em saída no console/terminal (vai parar em logs)",
     "id": "11e13569be",
     "dados": [
      "credencial"
     ],
     "fontes": [
      "L54 · variável de ambiente SPTRANS_TOKEN",
      "L57 · leitura do arquivo .env"
     ]
    }
   ],
   "sanitizados": [
    {
     "arquivo": "servidor_sbp.py",
     "linha": 131,
     "codigo": "e.read(120).decode(errors='replace').replace(self.token, '***')",
     "tipos": [
      "credencial"
     ]
    },
    {
     "arquivo": "servidor_sbp.py",
     "linha": 133,
     "codigo": "str(e).replace(self.token, '***')",
     "tipos": [
      "credencial"
     ]
    }
   ]
  },
  {
   "id": "v1",
   "nome": "Embarque Assistido v1 (vulnerável)",
   "caminho": "prototipo/embarque_vulneravel.py",
   "arquivos": 1,
   "pii": [],
   "fluxos": [
    {
     "arquivo": "prototipo/embarque_vulneravel.py",
     "status": "VAZAMENTO",
     "severidade": "critica",
     "fonte": {
      "tipo": "saude",
      "linha": 24,
      "descricao": "parâmetro 'corpo_requisicao' → campo 'condicao'"
     },
     "sink": {
      "tipo": "mqtt_publico",
      "linha": 30,
      "descricao": "publicação em broker MQTT público (qualquer pessoa pode assinar o tópico)",
      "codigo": "broker.publish(TOPICO + '/embarque', json.dumps(aviso, ensure_ascii=False))"
     },
     "parcial": false,
     "explicacao": "Valor de dado de saúde (sensível, LGPD art. 11) chega em publicação em broker MQTT público (qualquer pessoa pode assinar o tópico)"
    },
    {
     "arquivo": "prototipo/embarque_vulneravel.py",
     "status": "VAZAMENTO",
     "severidade": "critica",
     "fonte": {
      "tipo": "saude",
      "linha": 24,
      "descricao": "parâmetro 'corpo_requisicao' → campo 'condicao'"
     },
     "sink": {
      "tipo": "llm",
      "linha": 32,
      "descricao": "envio para modelo de IA (LLM)",
      "codigo": "enviar_para_ia(ia, f\"Classifique a prioridade do embarque de {dados['nome']}, CPF {dados['cpf']}, condicao: {dados['condicao']}\")"
     },
     "parcial": false,
     "explicacao": "Valor de dado de saúde (sensível, LGPD art. 11) chega em envio para modelo de IA (LLM)"
    },
    {
     "arquivo": "prototipo/embarque_vulneravel.py",
     "status": "VAZAMENTO",
     "severidade": "alta",
     "fonte": {
      "tipo": "saude",
      "linha": 24,
      "descricao": "objeto 'dados' inteiro (contém condicao)"
     },
     "sink": {
      "tipo": "log",
      "linha": 26,
      "descricao": "registro em log",
      "codigo": "log.info('novo pedido de embarque assistido: %s' % dados)"
     },
     "parcial": false,
     "explicacao": "Valor de dado de saúde (sensível, LGPD art. 11) chega em registro em log"
    },
    {
     "arquivo": "prototipo/embarque_vulneravel.py",
     "status": "VAZAMENTO",
     "severidade": "alta",
     "fonte": {
      "tipo": "pessoal",
      "linha": 24,
      "descricao": "parâmetro 'corpo_requisicao' → campo 'nome'"
     },
     "sink": {
      "tipo": "mqtt_publico",
      "linha": 30,
      "descricao": "publicação em broker MQTT público (qualquer pessoa pode assinar o tópico)",
      "codigo": "broker.publish(TOPICO + '/embarque', json.dumps(aviso, ensure_ascii=False))"
     },
     "parcial": false,
     "explicacao": "Valor de dado pessoal chega em publicação em broker MQTT público (qualquer pessoa pode assinar o tópico)"
    },
    {
     "arquivo": "prototipo/embarque_vulneravel.py",
     "status": "VAZAMENTO",
     "severidade": "alta",
     "fonte": {
      "tipo": "pessoal",
      "linha": 24,
      "descricao": "parâmetro 'corpo_requisicao' → campo 'nome'"
     },
     "sink": {
      "tipo": "llm",
      "linha": 32,
      "descricao": "envio para modelo de IA (LLM)",
      "codigo": "enviar_para_ia(ia, f\"Classifique a prioridade do embarque de {dados['nome']}, CPF {dados['cpf']}, condicao: {dados['condicao']}\")"
     },
     "parcial": false,
     "explicacao": "Valor de dado pessoal chega em envio para modelo de IA (LLM)"
    },
    {
     "arquivo": "prototipo/embarque_vulneravel.py",
     "status": "VAZAMENTO",
     "severidade": "alta",
     "fonte": {
      "tipo": "saude",
      "linha": 24,
      "descricao": "parâmetro 'corpo_requisicao' → campo 'condicao'"
     },
     "sink": {
      "tipo": "arquivo",
      "linha": 35,
      "descricao": "gravação em arquivo",
      "codigo": "arquivo.write(f\"{dados['cpf']};{dados['nome']};{dados['condicao']};{dados['telefone']}\\n\")"
     },
     "parcial": false,
     "explicacao": "Valor de dado de saúde (sensível, LGPD art. 11) chega em gravação em arquivo"
    },
    {
     "arquivo": "prototipo/embarque_vulneravel.py",
     "status": "VAZAMENTO",
     "severidade": "media",
     "fonte": {
      "tipo": "entrada",
      "linha": 24,
      "descricao": "parâmetro 'corpo_requisicao'"
     },
     "sink": {
      "tipo": "log",
      "linha": 26,
      "descricao": "registro em log",
      "codigo": "log.info('novo pedido de embarque assistido: %s' % dados)"
     },
     "parcial": false,
     "explicacao": "Valor de dado enviado pelo cidadão chega em registro em log"
    },
    {
     "arquivo": "prototipo/embarque_vulneravel.py",
     "status": "VAZAMENTO",
     "severidade": "media",
     "fonte": {
      "tipo": "pessoal",
      "linha": 24,
      "descricao": "objeto 'dados' inteiro (contém cpf, nome, telefone)"
     },
     "sink": {
      "tipo": "log",
      "linha": 26,
      "descricao": "registro em log",
      "codigo": "log.info('novo pedido de embarque assistido: %s' % dados)"
     },
     "parcial": false,
     "explicacao": "Valor de dado pessoal chega em registro em log"
    },
    {
     "arquivo": "prototipo/embarque_vulneravel.py",
     "status": "VAZAMENTO",
     "severidade": "media",
     "fonte": {
      "tipo": "pessoal",
      "linha": 24,
      "descricao": "parâmetro 'corpo_requisicao' → campo 'nome'"
     },
     "sink": {
      "tipo": "arquivo",
      "linha": 35,
      "descricao": "gravação em arquivo",
      "codigo": "arquivo.write(f\"{dados['cpf']};{dados['nome']};{dados['condicao']};{dados['telefone']}\\n\")"
     },
     "parcial": false,
     "explicacao": "Valor de dado pessoal chega em gravação em arquivo"
    },
    {
     "arquivo": "prototipo/embarque_vulneravel.py",
     "status": "VAZAMENTO",
     "severidade": "media",
     "fonte": {
      "tipo": "pessoal",
      "linha": 24,
      "descricao": "parâmetro 'corpo_requisicao' → campo 'telefone'"
     },
     "sink": {
      "tipo": "console",
      "linha": 36,
      "descricao": "saída no console/terminal (vai parar em logs)",
      "codigo": "print('pedido registrado para', dados['nome'], 'tel', dados['telefone'])"
     },
     "parcial": false,
     "explicacao": "Valor de dado pessoal chega em saída no console/terminal (vai parar em logs)"
    }
   ],
   "fluxos_agrupados": [
    {
     "arquivo": "prototipo/embarque_vulneravel.py",
     "status": "VAZAMENTO",
     "severidade": "critica",
     "fonte": {
      "tipo": "saude",
      "linha": 24,
      "descricao": "parâmetro 'corpo_requisicao' → campo 'condicao'"
     },
     "sink": {
      "tipo": "mqtt_publico",
      "linha": 30,
      "descricao": "publicação em broker MQTT público (qualquer pessoa pode assinar o tópico)",
      "codigo": "broker.publish(TOPICO + '/embarque', json.dumps(aviso, ensure_ascii=False))"
     },
     "parcial": false,
     "explicacao": "Valor de dado de saúde (sensível, LGPD art. 11) chega em publicação em broker MQTT público (qualquer pessoa pode assinar o tópico)",
     "id": "2048e8985d",
     "dados": [
      "dado pessoal",
      "saúde"
     ],
     "fontes": [
      "L24 · parâmetro 'corpo_requisicao' → campo 'condicao'",
      "L24 · parâmetro 'corpo_requisicao' → campo 'nome'"
     ]
    },
    {
     "arquivo": "prototipo/embarque_vulneravel.py",
     "status": "VAZAMENTO",
     "severidade": "critica",
     "fonte": {
      "tipo": "saude",
      "linha": 24,
      "descricao": "parâmetro 'corpo_requisicao' → campo 'condicao'"
     },
     "sink": {
      "tipo": "llm",
      "linha": 32,
      "descricao": "envio para modelo de IA (LLM)",
      "codigo": "enviar_para_ia(ia, f\"Classifique a prioridade do embarque de {dados['nome']}, CPF {dados['cpf']}, condicao: {dados['condicao']}\")"
     },
     "parcial": false,
     "explicacao": "Valor de dado de saúde (sensível, LGPD art. 11) chega em envio para modelo de IA (LLM)",
     "id": "e9ad2744cc",
     "dados": [
      "dado pessoal",
      "saúde"
     ],
     "fontes": [
      "L24 · parâmetro 'corpo_requisicao' → campo 'condicao'",
      "L24 · parâmetro 'corpo_requisicao' → campo 'nome'"
     ]
    },
    {
     "arquivo": "prototipo/embarque_vulneravel.py",
     "status": "VAZAMENTO",
     "severidade": "alta",
     "fonte": {
      "tipo": "saude",
      "linha": 24,
      "descricao": "objeto 'dados' inteiro (contém condicao)"
     },
     "sink": {
      "tipo": "log",
      "linha": 26,
      "descricao": "registro em log",
      "codigo": "log.info('novo pedido de embarque assistido: %s' % dados)"
     },
     "parcial": false,
     "explicacao": "Valor de dado de saúde (sensível, LGPD art. 11) chega em registro em log",
     "id": "4a538bbbdb",
     "dados": [
      "dado do cidadão",
      "dado pessoal",
      "saúde"
     ],
     "fontes": [
      "L24 · objeto 'dados' inteiro (contém condicao)",
      "L24 · objeto 'dados' inteiro (contém cpf, nome, telefone)",
      "L24 · parâmetro 'corpo_requisicao'"
     ]
    },
    {
     "arquivo": "prototipo/embarque_vulneravel.py",
     "status": "VAZAMENTO",
     "severidade": "alta",
     "fonte": {
      "tipo": "saude",
      "linha": 24,
      "descricao": "parâmetro 'corpo_requisicao' → campo 'condicao'"
     },
     "sink": {
      "tipo": "arquivo",
      "linha": 35,
      "descricao": "gravação em arquivo",
      "codigo": "arquivo.write(f\"{dados['cpf']};{dados['nome']};{dados['condicao']};{dados['telefone']}\\n\")"
     },
     "parcial": false,
     "explicacao": "Valor de dado de saúde (sensível, LGPD art. 11) chega em gravação em arquivo",
     "id": "1c44e0c028",
     "dados": [
      "dado pessoal",
      "saúde"
     ],
     "fontes": [
      "L24 · parâmetro 'corpo_requisicao' → campo 'condicao'",
      "L24 · parâmetro 'corpo_requisicao' → campo 'nome'"
     ]
    },
    {
     "arquivo": "prototipo/embarque_vulneravel.py",
     "status": "VAZAMENTO",
     "severidade": "media",
     "fonte": {
      "tipo": "pessoal",
      "linha": 24,
      "descricao": "parâmetro 'corpo_requisicao' → campo 'telefone'"
     },
     "sink": {
      "tipo": "console",
      "linha": 36,
      "descricao": "saída no console/terminal (vai parar em logs)",
      "codigo": "print('pedido registrado para', dados['nome'], 'tel', dados['telefone'])"
     },
     "parcial": false,
     "explicacao": "Valor de dado pessoal chega em saída no console/terminal (vai parar em logs)",
     "id": "d98b4fcfd7",
     "dados": [
      "dado pessoal"
     ],
     "fontes": [
      "L24 · parâmetro 'corpo_requisicao' → campo 'telefone'"
     ]
    }
   ],
   "sanitizados": []
  },
  {
   "id": "v2",
   "nome": "Embarque Assistido v2 (corrigida)",
   "caminho": "prototipo/embarque_seguro.py",
   "arquivos": 1,
   "pii": [],
   "fluxos": [],
   "fluxos_agrupados": [],
   "sanitizados": [
    {
     "arquivo": "prototipo/embarque_seguro.py",
     "linha": 54,
     "codigo": "pseudonimizar(dados['cpf'])",
     "tipos": [
      "pessoal"
     ]
    },
    {
     "arquivo": "prototipo/embarque_seguro.py",
     "linha": 55,
     "codigo": "minimizar_apoio(dados['condicao'])",
     "tipos": [
      "saude"
     ]
    },
    {
     "arquivo": "prototipo/embarque_seguro.py",
     "linha": 62,
     "codigo": "criptografar(dados)",
     "tipos": [
      "entrada",
      "pessoal",
      "saude"
     ]
    }
   ]
  }
 ],
 "runtime": [
  {
   "cenario": "antes",
   "modo_guardiao": "monitorar",
   "pedidos": 4,
   "pedidos_atendidos": 4,
   "dados_pessoais_que_chegaram_nas_saidas": {
    "mqtt_publico": 16,
    "log": 16,
    "llm": 8,
    "arquivo_texto": 12,
    "console": 4
   },
   "total_vazado": 56,
   "guardiao": {
    "bloqueado": 0,
    "mascarado": 0,
    "vazou": 20,
    "permitido (destino seguro)": 0
   },
   "eventos": [
    {
     "quando": "19:58:19",
     "destino": "log",
     "destino_desc": "log da aplicação",
     "contexto": "log.info",
     "categorias": [
      "contato",
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "Nome de pessoa",
       "mascara": "A*** B*** M***",
       "impressao": "f815225c"
      },
      {
       "tipo": "CPF",
       "mascara": "***.***.***-**",
       "impressao": "a289ff5f"
      },
      {
       "tipo": "Condição de saúde ou deficiência",
       "mascara": "[dado de saúde oculto]",
       "impressao": "aad722c7"
      },
      {
       "tipo": "Telefone celular",
       "mascara": "(**) *****-**80",
       "impressao": "58fdcf2d"
      }
     ],
     "assinatura": "0e83fa32",
     "acao": "vazou"
    },
    {
     "quando": "19:58:19",
     "destino": "mqtt_publico",
     "destino_desc": "broker MQTT público (broker.hivemq.com)",
     "contexto": "publish sbp-gs2026/totem/sbp-0001/embarque",
     "categorias": [
      "contato",
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "Campo de nome de pessoa",
       "mascara": "************",
       "impressao": "f815225c"
      },
      {
       "tipo": "Campo CPF",
       "mascara": "***.***.***-**",
       "impressao": "a289ff5f"
      },
      {
       "tipo": "Campo de saúde",
       "mascara": "[dado de saúde oculto]",
       "impressao": "aad722c7"
      },
      {
       "tipo": "Campo de contato",
       "mascara": "************",
       "impressao": "58fdcf2d"
      }
     ],
     "assinatura": "fb638f5c",
     "acao": "vazou"
    },
    {
     "quando": "19:58:19",
     "destino": "llm",
     "destino_desc": "modelo de IA",
     "contexto": "prompt para IA",
     "categorias": [
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "CPF",
       "mascara": "***.***.***-**",
       "impressao": "a289ff5f"
      },
      {
       "tipo": "Condição de saúde ou deficiência",
       "mascara": "[dado de saúde oculto]",
       "impressao": "aad722c7"
      }
     ],
     "assinatura": "5e53bb61",
     "acao": "vazou"
    },
    {
     "quando": "19:58:19",
     "destino": "arquivo_texto",
     "destino_desc": "arquivo de texto sem criptografia",
     "contexto": "gravação CSV",
     "categorias": [
      "contato",
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "CPF",
       "mascara": "***.***.***-**",
       "impressao": "a289ff5f"
      },
      {
       "tipo": "Condição de saúde ou deficiência",
       "mascara": "[dado de saúde oculto]",
       "impressao": "aad722c7"
      },
      {
       "tipo": "Telefone celular",
       "mascara": "(**) *****-**80",
       "impressao": "58fdcf2d"
      }
     ],
     "assinatura": "df168bf8",
     "acao": "vazou"
    },
    {
     "quando": "19:58:19",
     "destino": "log",
     "destino_desc": "log da aplicação",
     "contexto": "print no console",
     "categorias": [
      "contato"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "Telefone celular",
       "mascara": "(**) *****-**80",
       "impressao": "58fdcf2d"
      }
     ],
     "assinatura": "41996b94",
     "acao": "vazou"
    },
    {
     "quando": "19:58:19",
     "destino": "log",
     "destino_desc": "log da aplicação",
     "contexto": "log.info",
     "categorias": [
      "contato",
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "Nome de pessoa",
       "mascara": "C*** H*** D***",
       "impressao": "fe240451"
      },
      {
       "tipo": "CPF",
       "mascara": "***.***.***-**",
       "impressao": "aa405202"
      },
      {
       "tipo": "Condição de saúde ou deficiência",
       "mascara": "[dado de saúde oculto]",
       "impressao": "72692f12"
      },
      {
       "tipo": "Telefone celular",
       "mascara": "(**) *****-**06",
       "impressao": "86f3dfd9"
      }
     ],
     "assinatura": "4fae2851",
     "acao": "vazou"
    },
    {
     "quando": "19:58:19",
     "destino": "mqtt_publico",
     "destino_desc": "broker MQTT público (broker.hivemq.com)",
     "contexto": "publish sbp-gs2026/totem/sbp-0001/embarque",
     "categorias": [
      "contato",
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "Campo de nome de pessoa",
       "mascara": "************",
       "impressao": "fe240451"
      },
      {
       "tipo": "Campo CPF",
       "mascara": "***.***.***-**",
       "impressao": "aa405202"
      },
      {
       "tipo": "Campo de saúde",
       "mascara": "[dado de saúde oculto]",
       "impressao": "72692f12"
      },
      {
       "tipo": "Campo de contato",
       "mascara": "************",
       "impressao": "86f3dfd9"
      }
     ],
     "assinatura": "b2a3e0c4",
     "acao": "vazou"
    },
    {
     "quando": "19:58:19",
     "destino": "llm",
     "destino_desc": "modelo de IA",
     "contexto": "prompt para IA",
     "categorias": [
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "CPF",
       "mascara": "***.***.***-**",
       "impressao": "aa405202"
      },
      {
       "tipo": "Condição de saúde ou deficiência",
       "mascara": "[dado de saúde oculto]",
       "impressao": "72692f12"
      }
     ],
     "assinatura": "cabf7a9b",
     "acao": "vazou"
    },
    {
     "quando": "19:58:19",
     "destino": "arquivo_texto",
     "destino_desc": "arquivo de texto sem criptografia",
     "contexto": "gravação CSV",
     "categorias": [
      "contato",
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "CPF",
       "mascara": "***.***.***-**",
       "impressao": "aa405202"
      },
      {
       "tipo": "Condição de saúde ou deficiência",
       "mascara": "[dado de saúde oculto]",
       "impressao": "72692f12"
      },
      {
       "tipo": "Telefone celular",
       "mascara": "(**) *****-**06",
       "impressao": "86f3dfd9"
      }
     ],
     "assinatura": "978193bf",
     "acao": "vazou"
    },
    {
     "quando": "19:58:19",
     "destino": "log",
     "destino_desc": "log da aplicação",
     "contexto": "print no console",
     "categorias": [
      "contato"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "Telefone celular",
       "mascara": "(**) *****-**06",
       "impressao": "86f3dfd9"
      }
     ],
     "assinatura": "65ac68a7",
     "acao": "vazou"
    },
    {
     "quando": "19:58:19",
     "destino": "log",
     "destino_desc": "log da aplicação",
     "contexto": "log.info",
     "categorias": [
      "contato",
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "Nome de pessoa",
       "mascara": "J*** R***",
       "impressao": "faef13d0"
      },
      {
       "tipo": "CPF",
       "mascara": "***.***.***-**",
       "impressao": "7c3e752d"
      },
      {
       "tipo": "Condição de saúde ou deficiência",
       "mascara": "[dado de saúde oculto]",
       "impressao": "e816ed23"
      },
      {
       "tipo": "Telefone celular",
       "mascara": "(**) *****-**14",
       "impressao": "db6a9e3b"
      }
     ],
     "assinatura": "872f111e",
     "acao": "vazou"
    },
    {
     "quando": "19:58:19",
     "destino": "mqtt_publico",
     "destino_desc": "broker MQTT público (broker.hivemq.com)",
     "contexto": "publish sbp-gs2026/totem/sbp-0001/embarque",
     "categorias": [
      "contato",
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "Campo de nome de pessoa",
       "mascara": "************",
       "impressao": "faef13d0"
      },
      {
       "tipo": "Campo CPF",
       "mascara": "***.***.***-**",
       "impressao": "7c3e752d"
      },
      {
       "tipo": "Campo de saúde",
       "mascara": "[dado de saúde oculto]",
       "impressao": "e816ed23"
      },
      {
       "tipo": "Campo de contato",
       "mascara": "************",
       "impressao": "db6a9e3b"
      }
     ],
     "assinatura": "3e0c043f",
     "acao": "vazou"
    },
    {
     "quando": "19:58:19",
     "destino": "llm",
     "destino_desc": "modelo de IA",
     "contexto": "prompt para IA",
     "categorias": [
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "CPF",
       "mascara": "***.***.***-**",
       "impressao": "7c3e752d"
      },
      {
       "tipo": "Condição de saúde ou deficiência",
       "mascara": "[dado de saúde oculto]",
       "impressao": "e816ed23"
      }
     ],
     "assinatura": "152cfbc5",
     "acao": "vazou"
    },
    {
     "quando": "19:58:19",
     "destino": "arquivo_texto",
     "destino_desc": "arquivo de texto sem criptografia",
     "contexto": "gravação CSV",
     "categorias": [
      "contato",
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "CPF",
       "mascara": "***.***.***-**",
       "impressao": "7c3e752d"
      },
      {
       "tipo": "Condição de saúde ou deficiência",
       "mascara": "[dado de saúde oculto]",
       "impressao": "e816ed23"
      },
      {
       "tipo": "Telefone celular",
       "mascara": "(**) *****-**14",
       "impressao": "db6a9e3b"
      }
     ],
     "assinatura": "090774dd",
     "acao": "vazou"
    },
    {
     "quando": "19:58:19",
     "destino": "log",
     "destino_desc": "log da aplicação",
     "contexto": "print no console",
     "categorias": [
      "contato"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "Telefone celular",
       "mascara": "(**) *****-**14",
       "impressao": "db6a9e3b"
      }
     ],
     "assinatura": "d38a23fa",
     "acao": "vazou"
    },
    {
     "quando": "19:58:19",
     "destino": "log",
     "destino_desc": "log da aplicação",
     "contexto": "log.info",
     "categorias": [
      "contato",
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "Nome de pessoa",
       "mascara": "P*** S*** L***",
       "impressao": "124385b9"
      },
      {
       "tipo": "CPF",
       "mascara": "***.***.***-**",
       "impressao": "1e0b721e"
      },
      {
       "tipo": "Condição de saúde ou deficiência",
       "mascara": "[dado de saúde oculto]",
       "impressao": "07102597"
      },
      {
       "tipo": "Telefone celular",
       "mascara": "(**) *****-**05",
       "impressao": "1a2dbc62"
      }
     ],
     "assinatura": "3472983a",
     "acao": "vazou"
    },
    {
     "quando": "19:58:19",
     "destino": "mqtt_publico",
     "destino_desc": "broker MQTT público (broker.hivemq.com)",
     "contexto": "publish sbp-gs2026/totem/sbp-0001/embarque",
     "categorias": [
      "contato",
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "Campo de nome de pessoa",
       "mascara": "************",
       "impressao": "124385b9"
      },
      {
       "tipo": "Campo CPF",
       "mascara": "***.***.***-**",
       "impressao": "1e0b721e"
      },
      {
       "tipo": "Campo de saúde",
       "mascara": "[dado de saúde oculto]",
       "impressao": "07102597"
      },
      {
       "tipo": "Campo de contato",
       "mascara": "************",
       "impressao": "1a2dbc62"
      }
     ],
     "assinatura": "2922899d",
     "acao": "vazou"
    },
    {
     "quando": "19:58:19",
     "destino": "llm",
     "destino_desc": "modelo de IA",
     "contexto": "prompt para IA",
     "categorias": [
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "CPF",
       "mascara": "***.***.***-**",
       "impressao": "1e0b721e"
      },
      {
       "tipo": "Condição de saúde ou deficiência",
       "mascara": "[dado de saúde oculto]",
       "impressao": "07102597"
      }
     ],
     "assinatura": "5d562ef6",
     "acao": "vazou"
    },
    {
     "quando": "19:58:19",
     "destino": "arquivo_texto",
     "destino_desc": "arquivo de texto sem criptografia",
     "contexto": "gravação CSV",
     "categorias": [
      "contato",
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "CPF",
       "mascara": "***.***.***-**",
       "impressao": "1e0b721e"
      },
      {
       "tipo": "Condição de saúde ou deficiência",
       "mascara": "[dado de saúde oculto]",
       "impressao": "07102597"
      },
      {
       "tipo": "Telefone celular",
       "mascara": "(**) *****-**05",
       "impressao": "1a2dbc62"
      }
     ],
     "assinatura": "746c406f",
     "acao": "vazou"
    },
    {
     "quando": "19:58:19",
     "destino": "log",
     "destino_desc": "log da aplicação",
     "contexto": "print no console",
     "categorias": [
      "contato"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "Telefone celular",
       "mascara": "(**) *****-**05",
       "impressao": "1a2dbc62"
      }
     ],
     "assinatura": "eadaf03f",
     "acao": "vazou"
    }
   ],
   "mensagens_broker": 4,
   "prompts_ia": 4
  },
  {
   "cenario": "guardiao",
   "modo_guardiao": "bloquear",
   "pedidos": 4,
   "pedidos_atendidos": 4,
   "dados_pessoais_que_chegaram_nas_saidas": {
    "mqtt_publico": 0,
    "log": 0,
    "llm": 0,
    "arquivo_texto": 0,
    "console": 0
   },
   "total_vazado": 0,
   "guardiao": {
    "bloqueado": 20,
    "mascarado": 0,
    "vazou": 0,
    "permitido (destino seguro)": 0
   },
   "eventos": [
    {
     "quando": "19:58:19",
     "destino": "log",
     "destino_desc": "log da aplicação",
     "contexto": "log.info",
     "categorias": [
      "contato",
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "Nome de pessoa",
       "mascara": "A*** B*** M***",
       "impressao": "f815225c"
      },
      {
       "tipo": "CPF",
       "mascara": "***.***.***-**",
       "impressao": "a289ff5f"
      },
      {
       "tipo": "Condição de saúde ou deficiência",
       "mascara": "[dado de saúde oculto]",
       "impressao": "aad722c7"
      },
      {
       "tipo": "Telefone celular",
       "mascara": "(**) *****-**80",
       "impressao": "58fdcf2d"
      }
     ],
     "assinatura": "0e83fa32",
     "acao": "bloqueado"
    },
    {
     "quando": "19:58:19",
     "destino": "mqtt_publico",
     "destino_desc": "broker MQTT público (broker.hivemq.com)",
     "contexto": "publish sbp-gs2026/totem/sbp-0001/embarque",
     "categorias": [
      "contato",
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "Campo de nome de pessoa",
       "mascara": "************",
       "impressao": "f815225c"
      },
      {
       "tipo": "Campo CPF",
       "mascara": "***.***.***-**",
       "impressao": "a289ff5f"
      },
      {
       "tipo": "Campo de saúde",
       "mascara": "[dado de saúde oculto]",
       "impressao": "aad722c7"
      },
      {
       "tipo": "Campo de contato",
       "mascara": "************",
       "impressao": "58fdcf2d"
      }
     ],
     "assinatura": "fb638f5c",
     "acao": "bloqueado"
    },
    {
     "quando": "19:58:19",
     "destino": "llm",
     "destino_desc": "modelo de IA",
     "contexto": "prompt para IA",
     "categorias": [
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "CPF",
       "mascara": "***.***.***-**",
       "impressao": "a289ff5f"
      },
      {
       "tipo": "Condição de saúde ou deficiência",
       "mascara": "[dado de saúde oculto]",
       "impressao": "aad722c7"
      }
     ],
     "assinatura": "5e53bb61",
     "acao": "bloqueado"
    },
    {
     "quando": "19:58:19",
     "destino": "arquivo_texto",
     "destino_desc": "arquivo de texto sem criptografia",
     "contexto": "gravação CSV",
     "categorias": [
      "contato",
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "CPF",
       "mascara": "***.***.***-**",
       "impressao": "a289ff5f"
      },
      {
       "tipo": "Condição de saúde ou deficiência",
       "mascara": "[dado de saúde oculto]",
       "impressao": "aad722c7"
      },
      {
       "tipo": "Telefone celular",
       "mascara": "(**) *****-**80",
       "impressao": "58fdcf2d"
      }
     ],
     "assinatura": "df168bf8",
     "acao": "bloqueado"
    },
    {
     "quando": "19:58:19",
     "destino": "log",
     "destino_desc": "log da aplicação",
     "contexto": "print no console",
     "categorias": [
      "contato"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "Telefone celular",
       "mascara": "(**) *****-**80",
       "impressao": "58fdcf2d"
      }
     ],
     "assinatura": "41996b94",
     "acao": "bloqueado"
    },
    {
     "quando": "19:58:19",
     "destino": "log",
     "destino_desc": "log da aplicação",
     "contexto": "log.info",
     "categorias": [
      "contato",
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "Nome de pessoa",
       "mascara": "C*** H*** D***",
       "impressao": "fe240451"
      },
      {
       "tipo": "CPF",
       "mascara": "***.***.***-**",
       "impressao": "aa405202"
      },
      {
       "tipo": "Condição de saúde ou deficiência",
       "mascara": "[dado de saúde oculto]",
       "impressao": "72692f12"
      },
      {
       "tipo": "Telefone celular",
       "mascara": "(**) *****-**06",
       "impressao": "86f3dfd9"
      }
     ],
     "assinatura": "4fae2851",
     "acao": "bloqueado"
    },
    {
     "quando": "19:58:19",
     "destino": "mqtt_publico",
     "destino_desc": "broker MQTT público (broker.hivemq.com)",
     "contexto": "publish sbp-gs2026/totem/sbp-0001/embarque",
     "categorias": [
      "contato",
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "Campo de nome de pessoa",
       "mascara": "************",
       "impressao": "fe240451"
      },
      {
       "tipo": "Campo CPF",
       "mascara": "***.***.***-**",
       "impressao": "aa405202"
      },
      {
       "tipo": "Campo de saúde",
       "mascara": "[dado de saúde oculto]",
       "impressao": "72692f12"
      },
      {
       "tipo": "Campo de contato",
       "mascara": "************",
       "impressao": "86f3dfd9"
      }
     ],
     "assinatura": "b2a3e0c4",
     "acao": "bloqueado"
    },
    {
     "quando": "19:58:19",
     "destino": "llm",
     "destino_desc": "modelo de IA",
     "contexto": "prompt para IA",
     "categorias": [
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "CPF",
       "mascara": "***.***.***-**",
       "impressao": "aa405202"
      },
      {
       "tipo": "Condição de saúde ou deficiência",
       "mascara": "[dado de saúde oculto]",
       "impressao": "72692f12"
      }
     ],
     "assinatura": "cabf7a9b",
     "acao": "bloqueado"
    },
    {
     "quando": "19:58:19",
     "destino": "arquivo_texto",
     "destino_desc": "arquivo de texto sem criptografia",
     "contexto": "gravação CSV",
     "categorias": [
      "contato",
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "CPF",
       "mascara": "***.***.***-**",
       "impressao": "aa405202"
      },
      {
       "tipo": "Condição de saúde ou deficiência",
       "mascara": "[dado de saúde oculto]",
       "impressao": "72692f12"
      },
      {
       "tipo": "Telefone celular",
       "mascara": "(**) *****-**06",
       "impressao": "86f3dfd9"
      }
     ],
     "assinatura": "978193bf",
     "acao": "bloqueado"
    },
    {
     "quando": "19:58:19",
     "destino": "log",
     "destino_desc": "log da aplicação",
     "contexto": "print no console",
     "categorias": [
      "contato"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "Telefone celular",
       "mascara": "(**) *****-**06",
       "impressao": "86f3dfd9"
      }
     ],
     "assinatura": "65ac68a7",
     "acao": "bloqueado"
    },
    {
     "quando": "19:58:19",
     "destino": "log",
     "destino_desc": "log da aplicação",
     "contexto": "log.info",
     "categorias": [
      "contato",
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "Nome de pessoa",
       "mascara": "J*** R***",
       "impressao": "faef13d0"
      },
      {
       "tipo": "CPF",
       "mascara": "***.***.***-**",
       "impressao": "7c3e752d"
      },
      {
       "tipo": "Condição de saúde ou deficiência",
       "mascara": "[dado de saúde oculto]",
       "impressao": "e816ed23"
      },
      {
       "tipo": "Telefone celular",
       "mascara": "(**) *****-**14",
       "impressao": "db6a9e3b"
      }
     ],
     "assinatura": "872f111e",
     "acao": "bloqueado"
    },
    {
     "quando": "19:58:19",
     "destino": "mqtt_publico",
     "destino_desc": "broker MQTT público (broker.hivemq.com)",
     "contexto": "publish sbp-gs2026/totem/sbp-0001/embarque",
     "categorias": [
      "contato",
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "Campo de nome de pessoa",
       "mascara": "************",
       "impressao": "faef13d0"
      },
      {
       "tipo": "Campo CPF",
       "mascara": "***.***.***-**",
       "impressao": "7c3e752d"
      },
      {
       "tipo": "Campo de saúde",
       "mascara": "[dado de saúde oculto]",
       "impressao": "e816ed23"
      },
      {
       "tipo": "Campo de contato",
       "mascara": "************",
       "impressao": "db6a9e3b"
      }
     ],
     "assinatura": "3e0c043f",
     "acao": "bloqueado"
    },
    {
     "quando": "19:58:19",
     "destino": "llm",
     "destino_desc": "modelo de IA",
     "contexto": "prompt para IA",
     "categorias": [
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "CPF",
       "mascara": "***.***.***-**",
       "impressao": "7c3e752d"
      },
      {
       "tipo": "Condição de saúde ou deficiência",
       "mascara": "[dado de saúde oculto]",
       "impressao": "e816ed23"
      }
     ],
     "assinatura": "152cfbc5",
     "acao": "bloqueado"
    },
    {
     "quando": "19:58:19",
     "destino": "arquivo_texto",
     "destino_desc": "arquivo de texto sem criptografia",
     "contexto": "gravação CSV",
     "categorias": [
      "contato",
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "CPF",
       "mascara": "***.***.***-**",
       "impressao": "7c3e752d"
      },
      {
       "tipo": "Condição de saúde ou deficiência",
       "mascara": "[dado de saúde oculto]",
       "impressao": "e816ed23"
      },
      {
       "tipo": "Telefone celular",
       "mascara": "(**) *****-**14",
       "impressao": "db6a9e3b"
      }
     ],
     "assinatura": "090774dd",
     "acao": "bloqueado"
    },
    {
     "quando": "19:58:19",
     "destino": "log",
     "destino_desc": "log da aplicação",
     "contexto": "print no console",
     "categorias": [
      "contato"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "Telefone celular",
       "mascara": "(**) *****-**14",
       "impressao": "db6a9e3b"
      }
     ],
     "assinatura": "d38a23fa",
     "acao": "bloqueado"
    },
    {
     "quando": "19:58:19",
     "destino": "log",
     "destino_desc": "log da aplicação",
     "contexto": "log.info",
     "categorias": [
      "contato",
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "Nome de pessoa",
       "mascara": "P*** S*** L***",
       "impressao": "124385b9"
      },
      {
       "tipo": "CPF",
       "mascara": "***.***.***-**",
       "impressao": "1e0b721e"
      },
      {
       "tipo": "Condição de saúde ou deficiência",
       "mascara": "[dado de saúde oculto]",
       "impressao": "07102597"
      },
      {
       "tipo": "Telefone celular",
       "mascara": "(**) *****-**05",
       "impressao": "1a2dbc62"
      }
     ],
     "assinatura": "3472983a",
     "acao": "bloqueado"
    },
    {
     "quando": "19:58:19",
     "destino": "mqtt_publico",
     "destino_desc": "broker MQTT público (broker.hivemq.com)",
     "contexto": "publish sbp-gs2026/totem/sbp-0001/embarque",
     "categorias": [
      "contato",
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "Campo de nome de pessoa",
       "mascara": "************",
       "impressao": "124385b9"
      },
      {
       "tipo": "Campo CPF",
       "mascara": "***.***.***-**",
       "impressao": "1e0b721e"
      },
      {
       "tipo": "Campo de saúde",
       "mascara": "[dado de saúde oculto]",
       "impressao": "07102597"
      },
      {
       "tipo": "Campo de contato",
       "mascara": "************",
       "impressao": "1a2dbc62"
      }
     ],
     "assinatura": "2922899d",
     "acao": "bloqueado"
    },
    {
     "quando": "19:58:19",
     "destino": "llm",
     "destino_desc": "modelo de IA",
     "contexto": "prompt para IA",
     "categorias": [
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "CPF",
       "mascara": "***.***.***-**",
       "impressao": "1e0b721e"
      },
      {
       "tipo": "Condição de saúde ou deficiência",
       "mascara": "[dado de saúde oculto]",
       "impressao": "07102597"
      }
     ],
     "assinatura": "5d562ef6",
     "acao": "bloqueado"
    },
    {
     "quando": "19:58:19",
     "destino": "arquivo_texto",
     "destino_desc": "arquivo de texto sem criptografia",
     "contexto": "gravação CSV",
     "categorias": [
      "contato",
      "identificador",
      "saude"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "CPF",
       "mascara": "***.***.***-**",
       "impressao": "1e0b721e"
      },
      {
       "tipo": "Condição de saúde ou deficiência",
       "mascara": "[dado de saúde oculto]",
       "impressao": "07102597"
      },
      {
       "tipo": "Telefone celular",
       "mascara": "(**) *****-**05",
       "impressao": "1a2dbc62"
      }
     ],
     "assinatura": "746c406f",
     "acao": "bloqueado"
    },
    {
     "quando": "19:58:19",
     "destino": "log",
     "destino_desc": "log da aplicação",
     "contexto": "print no console",
     "categorias": [
      "contato"
     ],
     "detectado_por": "conteúdo",
     "itens": [
      {
       "tipo": "Telefone celular",
       "mascara": "(**) *****-**05",
       "impressao": "1a2dbc62"
      }
     ],
     "assinatura": "eadaf03f",
     "acao": "bloqueado"
    }
   ],
   "mensagens_broker": 0,
   "prompts_ia": 0
  },
  {
   "cenario": "corrigido",
   "modo_guardiao": "bloquear",
   "pedidos": 4,
   "pedidos_atendidos": 4,
   "dados_pessoais_que_chegaram_nas_saidas": {
    "mqtt_publico": 0,
    "log": 0,
    "llm": 0,
    "arquivo_texto": 0,
    "console": 0
   },
   "total_vazado": 0,
   "guardiao": {
    "bloqueado": 0,
    "mascarado": 0,
    "vazou": 0,
    "permitido (destino seguro)": 0
   },
   "eventos": [],
   "mensagens_broker": 4,
   "prompts_ia": 4
  }
 ],
 "risco": {
  "antes": {
   "indice": 70,
   "faixa": "alto",
   "soma": 36.5,
   "por_categoria": {
    "saude": 23.6,
    "identificador": 12.9
   },
   "contribuicoes": [
    {
     "tipo": "fluxo de vazamento",
     "categoria": "saude",
     "ref": "prototipo/embarque_vulneravel.py:30",
     "pontos": 10.0
    },
    {
     "tipo": "fluxo de vazamento",
     "categoria": "saude",
     "ref": "prototipo/embarque_vulneravel.py:32",
     "pontos": 7.0
    },
    {
     "tipo": "fluxo de vazamento",
     "categoria": "pessoal",
     "ref": "prototipo/embarque_vulneravel.py:30",
     "pontos": 4.800000000000001
    },
    {
     "tipo": "fluxo de vazamento",
     "categoria": "saude",
     "ref": "prototipo/embarque_vulneravel.py:26",
     "pontos": 3.5999999999999996
    },
    {
     "tipo": "fluxo de vazamento",
     "categoria": "pessoal",
     "ref": "prototipo/embarque_vulneravel.py:32",
     "pontos": 3.3600000000000003
    },
    {
     "tipo": "fluxo de vazamento",
     "categoria": "saude",
     "ref": "prototipo/embarque_vulneravel.py:35",
     "pontos": 3.0
    },
    {
     "tipo": "fluxo de vazamento",
     "categoria": "pessoal",
     "ref": "prototipo/embarque_vulneravel.py:26",
     "pontos": 1.4400000000000002
    },
    {
     "tipo": "fluxo de vazamento",
     "categoria": "pessoal",
     "ref": "prototipo/embarque_vulneravel.py:35",
     "pontos": 1.2000000000000002
    },
    {
     "tipo": "fluxo de vazamento",
     "categoria": "pessoal",
     "ref": "prototipo/embarque_vulneravel.py:36",
     "pontos": 1.2000000000000002
    },
    {
     "tipo": "fluxo de vazamento",
     "categoria": "entrada",
     "ref": "prototipo/embarque_vulneravel.py:26",
     "pontos": 0.8999999999999999
    }
   ]
  },
  "guardiao": {
   "indice": 11,
   "faixa": "baixo",
   "soma": 3.7,
   "por_categoria": {
    "saude": 2.4,
    "identificador": 1.2
   },
   "contribuicoes": [
    {
     "tipo": "fluxo bloqueado",
     "categoria": "saude",
     "ref": "prototipo/embarque_vulneravel.py:30",
     "pontos": 1.0
    },
    {
     "tipo": "fluxo bloqueado",
     "categoria": "saude",
     "ref": "prototipo/embarque_vulneravel.py:32",
     "pontos": 0.7000000000000001
    },
    {
     "tipo": "fluxo bloqueado",
     "categoria": "pessoal",
     "ref": "prototipo/embarque_vulneravel.py:30",
     "pontos": 0.4800000000000001
    },
    {
     "tipo": "fluxo bloqueado",
     "categoria": "saude",
     "ref": "prototipo/embarque_vulneravel.py:26",
     "pontos": 0.36
    },
    {
     "tipo": "fluxo bloqueado",
     "categoria": "pessoal",
     "ref": "prototipo/embarque_vulneravel.py:32",
     "pontos": 0.3360000000000001
    },
    {
     "tipo": "fluxo bloqueado",
     "categoria": "saude",
     "ref": "prototipo/embarque_vulneravel.py:35",
     "pontos": 0.30000000000000004
    },
    {
     "tipo": "fluxo bloqueado",
     "categoria": "pessoal",
     "ref": "prototipo/embarque_vulneravel.py:26",
     "pontos": 0.14400000000000002
    },
    {
     "tipo": "fluxo bloqueado",
     "categoria": "pessoal",
     "ref": "prototipo/embarque_vulneravel.py:35",
     "pontos": 0.12000000000000002
    },
    {
     "tipo": "fluxo bloqueado",
     "categoria": "pessoal",
     "ref": "prototipo/embarque_vulneravel.py:36",
     "pontos": 0.12000000000000002
    },
    {
     "tipo": "fluxo bloqueado",
     "categoria": "entrada",
     "ref": "prototipo/embarque_vulneravel.py:26",
     "pontos": 0.09
    }
   ]
  },
  "corrigido": {
   "indice": 0,
   "faixa": "baixo",
   "soma": 0,
   "por_categoria": {},
   "contribuicoes": []
  },
  "sbp": {
   "indice": 49,
   "faixa": "moderado",
   "soma": 20.4,
   "por_categoria": {
    "credencial": 20.4
   },
   "contribuicoes": [
    {
     "tipo": "fluxo de vazamento",
     "categoria": "credencial",
     "ref": "servidor_sbp.py:104",
     "pontos": 9.0
    },
    {
     "tipo": "fluxo de vazamento",
     "categoria": "credencial",
     "ref": "servidor_sbp.py:126",
     "pontos": 9.0
    },
    {
     "tipo": "dado em repouso",
     "categoria": "credencial",
     "ref": ".env:1",
     "pontos": 0.8999999999999999
    },
    {
     "tipo": "fluxo de vazamento",
     "categoria": "credencial",
     "ref": "servidor_sbp.py:124",
     "pontos": 0.5
    },
    {
     "tipo": "fluxo de vazamento",
     "categoria": "credencial",
     "ref": "servidor_sbp.py:314",
     "pontos": 0.5
    },
    {
     "tipo": "fluxo de vazamento",
     "categoria": "credencial",
     "ref": "servidor_sbp.py:314",
     "pontos": 0.5
    }
   ]
  }
 },
 "destinos_bloqueados": [
  "arquivo_texto",
  "llm",
  "log",
  "mqtt_publico"
 ],
 "alertas": {
  "b3b7adeab4": {
   "titulo": "Dado sensível trafega em HTTP",
   "risco_cidadao": "Pode expor credenciais em caso de falha de HTTPS.",
   "impacto": "Contraria a LGPD art. 46 (dever de segurança).",
   "como_corrigir": "Remova as URLs http:// da lista de bases e gere um erro se o HTTPS falhar.",
   "severidade": "alta",
   "fonte": "IA local (qwen2.5:7b)"
  },
  "c2d340d35f": {
   "titulo": "Dado sensível trafega em HTTP",
   "risco_cidadao": "Pode expor credenciais em caso de falha de HTTPS, levando a roubos de identidade.",
   "impacto": "Contraria a LGPD art. 46 (dever de segurança).",
   "como_corrigir": "Remova as URLs http:// da lista de bases e gere um erro se o HTTPS falhar.",
   "severidade": "alta",
   "fonte": "IA local (qwen2.5:7b)"
  },
  "137bdbeb61": {
   "titulo": "Credencial impressa no console",
   "risco_cidadao": "Exposição do token de acesso, podendo ser usado por maliciosos.",
   "impacto": "Contraria a LGPD art. 46 (dever de segurança).",
   "como_corrigir": "Remova a impressão do token no console e registre apenas que a credencial foi carregada com sucesso.",
   "severidade": "baixa",
   "fonte": "IA local (qwen2.5:7b)"
  },
  "11e13569be": {
   "titulo": "Credencial impressa no console",
   "risco_cidadao": "Exposição de credenciais sensíveis.",
   "impacto": "Contraria a LGPD art. 46 (dever de segurança).",
   "como_corrigir": "Remova a impressão do token e registre apenas que a credencial foi carregada.",
   "severidade": "baixa",
   "fonte": "IA local (qwen2.5:7b)"
  },
  "4ea35331e6": {
   "titulo": "Credencial em arquivo .env",
   "risco_cidadao": "Pode expor credenciais sensíveis, levando a possíveis ataques.",
   "impacto": "Contraria a Art. 46 — segurança dos dados (credencial de acesso).",
   "como_corrigir": "Manter o .env fora do git, com permissão restrita, e em produção usar um cofre de segredos.",
   "severidade": "media",
   "fonte": "IA local (qwen2.5:7b)"
  },
  "2048e8985d": {
   "titulo": "Dado de saúde exposto publicamente",
   "risco_cidadao": "Pode ser usado para discriminação ou golpes.",
   "impacto": "Contraria a LGPD art. 11 (dado sensível de saúde).",
   "como_corrigir": "Apenas publique um ponto, linha e um ID pseudônimo. Use um broker privado com TLS e autenticação para o resto do conteúdo.",
   "severidade": "critica",
   "fonte": "IA local (qwen2.5:7b)"
  },
  "e9ad2744cc": {
   "titulo": "Vazamento de dados sensíveis",
   "risco_cidadao": "Pode expor diagnósticos pessoais, levando a discriminação ou uso indevido.",
   "impacto": "Contraria a LGPD art. 11 (dado sensível de saúde).",
   "como_corrigir": "Anonimize os dados antes de enviar para a IA, usando categorias gerais como 'apoio_visual' em vez de nomes, CPFs ou diagnósticos específicos.",
   "severidade": "critica",
   "fonte": "IA local (qwen2.5:7b)"
  },
  "4a538bbbdb": {
   "titulo": "Log exibe dados de saúde sensíveis",
   "risco_cidadao": "Pode expor informações de saúde, levando a discriminação ou uso indevido.",
   "impacto": "Contraria a LGPD art. 11 (dado sensível de saúde).",
   "como_corrigir": "Modifique o código para registrar apenas um identificador pseudonimizado e o ponto/linha, não o objeto 'dados' inteiro.",
   "severidade": "alta",
   "fonte": "IA local (qwen2.5:7b)"
  },
  "1c44e0c028": {
   "titulo": "Gravação de dados sensíveis de saúde",
   "risco_cidadao": "Pode expor informações pessoais e de saúde, levando a discriminação ou uso indevido.",
   "impacto": "Contraria a LGPD art. 11 (dado sensível de saúde).",
   "como_corrigir": "Não grava os dados pessoais em texto puro; criptografe e restrinja o acesso.",
   "severidade": "alta",
   "fonte": "IA local (qwen2.5:7b)"
  },
  "d98b4fcfd7": {
   "titulo": "Dado pessoal exposto no console",
   "risco_cidadao": "Pode expor telefone da pessoa com deficiência, levando a possíveis abusos.",
   "impacto": "Contraria a LGPD art. 6º, III (necessidade) e art. 46 (segurança).",
   "como_corrigir": "Remova a impressão de 'dados['nome']' e 'dados['telefone']' no print. Use um identificador pseudonimizado do pedido em seu lugar.",
   "severidade": "media",
   "fonte": "IA local (qwen2.5:7b)"
  }
 },
 "ia": {
  "modelo": "qwen2.5:7b",
  "local": true,
  "usada": true,
  "estatisticas": {
   "ia": 0,
   "cache": 10,
   "modelo_pronto": 0,
   "prompt_bloqueado": 0
  }
 },
 "verificacao": {
  "ok": true,
  "resumo": "nenhum valor sensível nos arquivos gerados",
  "arquivos": 10,
  "valores": 17,
  "texto": "Verificação automática de vazamento nos artefatos do SBP Guard\n17/11/2026 19:58\n\nValores sensíveis encontrados na varredura (guardados só em memória): 17\nArquivos gerados verificados: 10\nResultado: OK — nenhum valor sensível nos arquivos gerados\n"
 }
};
