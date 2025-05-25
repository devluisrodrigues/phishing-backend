# Phishing API - Sistema de Detecção de Phishing

## Sobre o Projeto

Este repositório representa uma API desenvolvida para detectar sites potencialmente maliciosos ou de phishing. A API analisa domínios por meio de diversos fatores de risco, incluindo:

- Idade do domínio
- Validade do certificado SSL
- Caracteres especiais no nome do domínio
- Número excessivo de subdomínios
- Uso de endereço IP como nome de domínio
- Uso de DNS dinâmico
- Semelhança com domínios conhecidos
- Redirecionamentos suspeitos
- Presença de formulários sensíveis

----

## Endpoints Principais

```http
GET /check-domains/?domains={dominio1,dominio2,dominio3}&severity={3}
```

Parâmetros:
- `domains`: Lista de domínios a serem verificados, separados por espaço. Os domínios devem são criptografados em base64.

- `severity`: Nível de severidade para filtragem dos resultados. Valores possíveis: 1 (baixo), 2 (médio), 3 (alto). O padrão é 1.

Resposta:
Uma json com um boolean indicando se o domínio é potencialmente malicioso ou não, e uma lista de fatores de risco identificados.

----

## Instalação
Para instalar as dependências do projeto, execute o seguinte comando:

```bash
python -m venv venv
source venv/bin/activate

pip install -r requirements.txt

fastapi run main.py
```

A API estará disponível em `http://localhost:8000`.

----

## Parâmetros de Configuração

Os parâmetros de configuração podem ser ajustados no arquivo `settings.py`. Os principais parâmetros incluem:

- `DOMAIN_AGE_THRESHOLD`: Idade mínima aceitável para um domínio (em dias).
- `THRESHOLD_SUBDOMAINS`: Número máximo aceitável de subdomínios.
- `LEVENSHTEIN_THRESHOLD`: Limiar para considerar domínios similares.
- `REDIRECT_THRESHOLD`: Número máximo aceitável de redirecionamentos.

----

## Referências:

- https://github.com/zer0h/top-1000000-domains/blob/master/top-10000-domains
- https://fastapi.tiangolo.com/
- https://pypi.org/project/python-whois/
- https://docs.python.org/3/library/ssl.html/
- https://oxylabs.io/blog/beautiful-soup-parsing-tutorial/
- https://www.nltk.org/api/nltk.metrics.distance.html/ 
- https://stackoverflow.com/questions/13482777/how-to-detect-when-a-site-check-redirects-to-another-page-using-the-requests-mod