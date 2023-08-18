from urllib.parse import urlparse
import socket
import re
import requests
from bs4 import BeautifulSoup
import whois
import numpy as np
from datetime import datetime
from urllib.parse import urlparse

def get_url_features(url):
    parsed_url = urlparse(url)
    
    full_url_length = len(url)
    hostname_length = len(parsed_url.netloc)
    
    return full_url_length, hostname_length

def get_bool(bool):
    return 1 if bool else 0

def get_domain_age(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        current_date = datetime.now()
        domain_age = (current_date - creation_date).days
        return domain_age
    except Exception as e:
        print("Error:", e)
        return -1
    

def get_page_rank(url):
    try:
        response = requests.get('https://www.prchecker.info/check_page_rank.php', params={'name': url})
        response.raise_for_status()  # Raise an exception for HTTP errors
        rank = int(response.text.strip())
        return rank
    except requests.exceptions.RequestException as e:
        print("Error:", e)
        return 0

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return 1  # Return 1 if the IP is valid
    except socket.error:
        return 0  # Return 0 if the IP is not valid
    
def is_empty_title(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        html_content = response.text
        soup = BeautifulSoup(html_content, 'html.parser')
        title = soup.find('title')
        if title:
            return 0  # Webpage has a title
        else:
            return 1  # Webpage title is missing
    except requests.exceptions.RequestException:
        return 1
    
def has_domain_in_title(url):
    try:
        parsed_url = urlparse(url)
        response = requests.get(url)
        response.raise_for_status()
        html_content = response.text
        soup = BeautifulSoup(html_content, 'html.parser')
        title = soup.find('title')
        if title:
            title_text = title.text.lower()
            domain = parsed_url.netloc.lower()
            return int(domain in title_text)
        else:
            return 0  # Webpage title is missing
    except requests.exceptions.RequestException:
        return 1 

def extract_features_from_url(url):
    parsed_url = urlparse(url)
    
    # Longitud de la URL
    length_url, length_hostname = get_url_features(url)
    
    # Detección de dirección IP
    try:
        ip_p = socket.gethostbyname(parsed_url.netloc)
        ip = is_valid_ip(ip_p)
    except socket.gaierror:
        ip = 0


    # Cantidad de puntos en la URL
    nb_dots = url.count('.')
    
    # Cantidad de signos de interrogación en la URL
    nb_qm = url.count('?')
    
    # Cantidad de signos de igual en la URL
    nb_eq = url.count('=')
    
    # Cantidad de barras en la URL
    nb_slash = url.count('/')
    
    # Cantidad de "www" en el hostname
    nb_www = parsed_url.netloc.count('www')
    
    # Proporción de dígitos en la URL
    ratio_digits_url = sum(c.isdigit() for c in url) / len(url)
    
    # Proporción de dígitos en el hostname
    ratio_digits_host = sum(c.isdigit() for c in parsed_url.netloc) / len(parsed_url.netloc)
    
    # Detección de dominio en subdominio
    tld_in_subdomain = get_bool(parsed_url.netloc.count('.') > 1 and parsed_url.path.count('.') == 0)
    
    # Prefijo y sufijo en el hostname
    prefix_suffix = parsed_url.netloc.count('-')
    
    # Longitud de la palabra más corta en el hostname
    shortest_word_host = min(len(word) for word in parsed_url.netloc.split('.'))
    
    # Longitud de las palabras más largas en el hostname
    longest_words_raw = max(len(word) for word in parsed_url.netloc.split('.'))
    
    # Longitud de la palabra más larga en la ruta
    longest_word_path = max(len(word) for word in parsed_url.path.split('/'))
    
    # Detección de indicios de phishing en la URL
    phish_hints = get_bool(bool(re.search(r'paypal|login|ebay|secure|signin|update|account|bank', url, re.I)))
    
    # Cantidad de enlaces dentro de la página web
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        nb_hyperlinks = len(soup.find_all('a'))
    except requests.exceptions.RequestException:
        nb_hyperlinks = 0
    
    # Proporción de enlaces internos dentro de la página web
    ratio_intHyperlinks = nb_hyperlinks / len(url)
    
    # Título vacío en la página
    empty_title = is_empty_title(url)

    # Edad del dominio
    domain_age = get_domain_age(url)
    
    # Presencia del dominio en el título de la página
    domain_in_title = has_domain_in_title(url)

    # Presencia en el índice de Google
    google_index = get_bool(bool(re.search(r'site:' + parsed_url.netloc, requests.get('https://www.google.com/search?q=site:' + parsed_url.netloc).text)))

    # PageRank
    page_rank = get_page_rank(url)
    
    return {
        'length_url': length_url,
        'length_hostname': length_hostname,
        'ip': ip,
        'nb_dots': nb_dots,
        'nb_qm': nb_qm,
        'nb_eq': nb_eq,
        'nb_slash': nb_slash,
        'nb_www': nb_www,
        'ratio_digits_url': ratio_digits_url,
        'ratio_digits_host': ratio_digits_host,
        'tld_in_subdomain': tld_in_subdomain,
        'prefix_suffix': prefix_suffix,
        'shortest_word_host': shortest_word_host,
        'longest_words_raw': longest_words_raw,
        'longest_word_path': longest_word_path,
        'phish_hints': phish_hints,
        'nb_hyperlinks': nb_hyperlinks,
        'ratio_intHyperlinks': ratio_intHyperlinks,
        'empty_title': empty_title,
        'domain_in_title': domain_in_title,
        'domain_age': domain_age,
        'google_index': google_index,
        'page_rank': page_rank,
    }

url = 'http://www.youtube.com/'
features = extract_features_from_url(url)

import joblib

ruta = 'model_phishing_extension_classifer'
modelo = joblib.load(ruta)
print("\n\n"+str(features))
numeric_data = [value for value in features.values() if isinstance(value, (int, float))]
print("\n\n"+str(numeric_data)+"\n\n")

input_data = np.array(numeric_data)
input_data = input_data.reshape(1,-1)
 # Ejemplo con las características del dato

# Realizar la predicción utilizando el modelo cargado
prediccion = modelo.predict(input_data)

# Imprimir la predicción
if prediccion == 0:
    print("Legitimo")
else:
    print("Phishing")