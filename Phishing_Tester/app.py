from flask import Flask, render_template, request, session, redirect, url_for
import numpy as np
from tensorflow.keras.models import load_model
import joblib
from urllib.parse import urlparse
import socket

# Função para analisar a URL e extrair as características
class URLAnalyzer:
    def __init__(self, url):
        self.url = url
        self.parsed_url = urlparse(url)

    def is_https(self):
        return int(self.parsed_url.scheme == 'https')

    def count_dots(self):
        return self.url.count('.')

    def url_length(self):
        return len(self.url)

    def count_digits(self):
        return sum(c.isdigit() for c in self.url)

    def count_special_characters(self):
        special_characters = ":;#!%~+_?=&[]"
        return sum(1 for c in self.url if c in special_characters)

    def count_hyphens(self):
        return self.url.count('-')

    def count_double_slashes(self):
        return self.url.count('//')

    def count_slashes(self):
        return self.url.count('/') - self.count_double_slashes()

    def count_at_symbols(self):
        return self.url.count('@')

    def is_ip_address(self):
        hostname = self.parsed_url.hostname
        if not hostname:
            return False

        try:
            socket.inet_pton(socket.AF_INET, hostname)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, hostname)
                return True
            except socket.error:
                return False

    def extract_features(self):
        features = [
            self.is_https(),
            self.count_dots(),
            self.url_length(),
            self.count_digits(),
            self.count_special_characters(),
            self.count_hyphens(),
            self.count_double_slashes(),
            self.count_slashes(),
            self.count_at_symbols(),
            self.is_ip_address()
        ]
        return features

# Função para carregar o modelo treinado e o scaler
def load_model_and_scaler():
    model = load_model('url_classifier_model.h5')  # Carregar o modelo
    scaler = joblib.load('scaler.pkl')  # Carregar o scaler
    return model, scaler

# Função para prever se a URL é phishing e retornar a probabilidade
def classify_url(model, scaler, url):
    analyzer = URLAnalyzer(url)  # Analisar a URL
    features = analyzer.extract_features()  # Extrair as características
    features_scaled = scaler.transform([features])  # Escalonar as características
    prediction = model.predict(features_scaled)  # Prever se a URL é phishing
    
    # A probabilidade de ser phishing será um valor entre 0 e 1, multiplicado por 100 para obter a porcentagem
    phishing_probability = float(prediction[0][0]) * 100  # Converte para float
    return round(phishing_probability, 2)  # Limita a duas casas decimais


# Criando o app Flask
app = Flask(__name__)

# Necessário para usar sessões no Flask
app.secret_key = 'supersecretkey'  # Chave secreta para a sessão

# Rota principal que renderiza o formulário HTML
@app.route('/', methods=['GET', 'POST'])
def index():
    # Se o formulário foi enviado (POST), processa a URL
    if request.method == 'POST':
        url = request.form['url']
        
        # Carregar o modelo e o scaler
        model, scaler = load_model_and_scaler()

        # Consultar a URL
        probability = classify_url(model, scaler, url)
        
        # Adicionar a URL e a probabilidade ao histórico da sessão
        if 'history' not in session:
            session['history'] = []
        
        session['history'].append({'url': url, 'probability': round(probability, 2)})
        
        # Salvar as alterações na sessão
        session.modified = True
        
        # Exibir o resultado
        return render_template('index.html', url=url, probability=probability, history=session['history'])
    
    # Caso o método seja GET ou não haja submissão, apenas exibe a página com o histórico (se houver)
    return render_template('index.html', url=None, probability=None, history=session.get('history', []))

# Rota para remover uma URL do histórico
@app.route('/remove/<int:index>', methods=['POST'])
def remove_url(index):
    """Remove uma URL do histórico pelo índice."""
    if 'history' in session and 0 <= index < len(session['history']):
        session['history'].pop(index)  # Remove o item no índice
        session.modified = True  # Indica que a sessão foi modificada
    return redirect(url_for('index'))  # Redireciona de volta à página inicial

# Rota para limpar todo o histórico
@app.route('/clear_history', methods=['POST'])
def clear_history():
    """Limpa todo o histórico de URLs."""
    session['history'] = []  # Limpa o histórico
    session.modified = True  # Indica que a sessão foi modificada
    return redirect(url_for('index'))  # Redireciona de volta à página inicial

if __name__ == '__main__':
    app.run(debug=True)
