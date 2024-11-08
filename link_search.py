import requests
from bs4 import BeautifulSoup

# URL da página que você quer raspar
url = 'https://www.unoesc.edu.br/'

# Fazendo a requisição HTTP para a página
response = requests.get(url)

# Analisando o conteúdo HTML da página
soup = BeautifulSoup(response.content, 'html.parser')

# Encontrando todos os elementos <a> (links) na página
links = soup.find_all('a')

# Imprimindo os links
for link in links:
    print(link.get('href'))