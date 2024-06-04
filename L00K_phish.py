import socket
import re
import asyncio
from datetime import datetime, timedelta
import requests
import nmap
from PIL import Image
import numpy as np
from urllib.parse import urlparse, urljoin
from selenium.webdriver.common.by import By
import ssl
import socket
import whois
from selenium import webdriver
from datetime import datetime
from bs4 import BeautifulSoup
from googlesearch import search

import socket
from concurrent.futures import ThreadPoolExecutor

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
import torch
import os

from sklearn.model_selection import train_test_split
from sklearn.model_selection import KFold
from xgboost import XGBClassifier
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier

from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score

top_phishing_domains = ['suspicious-domain1.com', 'suspicious-domain2.com']
top_phishing_ips = ['192.168.1.1', '192.168.1.2']

def logo(image_path, output_width=70, invert=False):
    # Caracteres ASCII usados para construir el texto de salida
    ASCII_CHARS = "@%#*+=-:. " if invert else " .:-=+*#%@"
    
    # Cargar la imagen y convertirla a escala de grises
    try:
        image = Image.open(image_path)
    except Exception as e:
        return f"Could not load image: {e}"

    # Calcular la altura usando la relación de aspecto
    width, height = image.size
    aspect_ratio = height / width
    output_height = int(output_width/2)

    # Redimensionar la imagen
    image = image.resize((output_width, output_height))

    # Convertir la imagen a escala de grises
    grayscale_image = image.convert("L")

    # Convertir cada píxel a un carácter ASCII
    pixels = np.array(grayscale_image)
    # Escalar los píxeles para que coincidan con la longitud de ASCII_CHARS
    scale_factor = len(ASCII_CHARS) / 256
    characters = "".join(ASCII_CHARS[int(pixel * scale_factor)] for pixel in pixels.flatten())

    # Dividir la cadena de caracteres en líneas
    ascii_image = "\n".join(characters[i:(i + output_width)] for i in range(0, len(characters), output_width))

    return ascii_image

def having_IP(url): # COMPRUEBA QUE LA URL NO INCLUYA UNA DIRECCIÓN IP
    partes = urlparse(url)
    # Extrae el hostname y el path
    hostname = partes.hostname
    dic = ['1','2','3','4','5','6','7','8','9','0']
    count = 0
    if hostname == None:
        return -1
    else:
        for r in hostname:
            if (r in  dic):
                count += 1
                if count <= 5:
                    return -1
    return 1
    
def lenght_URL(url): # REVISA LA LONGITUD DE LA URL
        if len(url) < 54:
            return 1
        elif len(url) > 75:
            return -1
        else:
            return 0
    
def tiny_URL(url): # REVISA QUE LA URL NO HAYA SIDO ACORTADA
    try:
        if url[-1] != "/":
            url = url + "/"
        respuesta = requests.head(url, allow_redirects=True)
        # Si la URL final es diferente de la original, fue una redirección
        if (respuesta.url != url):
            return -1
        else:
            return 1
    except requests.RequestException:
        return 1  # Si hay un error, asume que no es acortada
    
def having_arroba(url):
    if '@' in url:
        return -1
    else:
        return 1

def is_doubleslash_url(url):
    # Verificar si '//' aparece más allá de la parte del protocolo
    if url.startswith('http://'):
        slash_pos = url.find('//', 7)
    elif url.startswith('https://'):
        slash_pos = url.find('//', 8)
    else:
        # Para URLs relativas u otras que no comienzan con http:// o https://
        slash_pos = url.find('//')

    # Si '//' se encuentra más allá del protocolo, podría ser una URL de phishing
    if (slash_pos > 7) and (slash_pos < 10):
        return -1
    else:
        return 1

def contains_prefix_sufix(url):
    # Extrae el nombre de dominio de la URL
    nombre_dominio = urlparse(url).netloc
    # Verifica si el nombre de dominio contiene el símbolo "-"
    if "-" in nombre_dominio:
        return -1
    else:
        return 1  
    
def contains_subdomains(url):
    # Extrae el nombre de dominio de la URL
    dominio = urlparse(url).netloc
    
    # Elimina el prefijo "www." si existe
    if dominio.startswith('www.'):
        dominio = dominio[4:]
    
    # Cuenta los puntos restantes
    num_puntos = dominio.count('.')
    
    # Clasifica la URL según el número de puntos
    if num_puntos == 1:
        return 1
    elif num_puntos == 2:
        return 0
    else:
        return -1
    
def contains_SSL(url):
    emisores_confiables = [
                           "DigiCert Inc", "GlobalSign", "Sectigo Limited", 
                           "Symantec", "GoDaddy", "Entrust", 
                           "GeoTrust", 
                           "COMODO CA Limited",
                           "Thawte", 
                           "GEANT Vereniging",
                           "Microsoft Corporation",
                           "Google Trust Services LLC",
                           "RapidSSL", "Let’s Encrypt", 
                           "Network Solutions", "Trustwave", 
                           "SecureTrust",
                           "CERTUM", 
                           "Buypass", "SwissSign", "IdenTrust", "QuoVadis", 
                           "AC Camerfirma", "Actalis"
                           ]

    try:
        # Extrae el nombre de host de la URL
        hostname = urlparse(url).netloc
        # Establece una conexión segura
        contexto = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with contexto.wrap_socket(sock, server_hostname=hostname) as ssock:
                certificado = ssock.getpeercert()
                emisor = dict(x[0] for x in certificado['issuer'])
                emisor_nombre = emisor['organizationName']
                # Comprueba si el emisor es confiable
                if emisor_nombre in emisores_confiables:
                    # Verifica la edad del certificado                  
                    return 1
                else:
                    return 0
    except Exception as e:
        # Manejo de excepciones para casos como URL sin HTTPS, errores de conexión, etc.
        return -1

def domain_expiration(url):
    # Extrae el nombre de dominio de la URL
    nombre_dominio = urlparse(url).netloc
    try:
        w = whois.whois(nombre_dominio)
        # Obtiene la fecha de expiración del dominio
        expiracion = w.expiration_date

        # En algunos casos, 'expiration_date' puede ser una lista
        if type(expiracion) is list:
            expiracion = expiracion[0]
        
        # Calcula la diferencia en años
        hoy = datetime.now()
        diferencia = (expiracion - hoy).days / 365

        if diferencia <= 1:
            return -1
        else:
            return 1
    except Exception as e:
        # Si hay un error al obtener la información de WHOIS, manejar adecuadamente
        return -1    
    
def favicon_contains(url):
    try:
        # Obtener la página web
        response = requests.get(url)
        response.raise_for_status()  # Asegurar que la solicitud fue exitosa
        html_content = response.text

        # Parsear el HTML
        soup = BeautifulSoup(html_content, 'html.parser')
        favicon_link = soup.find("link", rel=lambda value: value and value.startswith("icon"))

        if favicon_link and favicon_link.has_attr('href'):
            favicon_url = favicon_link['href']
            # Parsear las URLs para obtener los dominios
            favicon_domain = urlparse(favicon_url).netloc
            page_domain = urlparse(url).netloc

            # Verificar si el favicon se carga desde un dominio externo
            if favicon_domain != page_domain:
                return -1
            else:
                return 1
        else:
            # No se encontró favicon
            return 1

    except requests.RequestException as e:
        print(f"Error al obtener la página: {e}")
        return -1
    except Exception as e:
        print(f"Ocurrió un error: {e}")
        return -1
    
def scan_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((host, port))
            return port, True
    except:
        return port, False

def classify_by_ports(host, start_port=1, end_port=1024, max_workers=100):
    domain = urlparse(host).netloc
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_port, domain, port) for port in range(start_port, end_port + 1)]
        open_ports = [port for port, is_open in (future.result() for future in futures) if is_open]
        if (443 in open_ports):
            open_ports.remove(443)
        if (8080 in open_ports):
            open_ports.remove(8080)
        if (80 in open_ports):
            open_ports.remove(80)
        if (53 in open_ports):
            open_ports.remove(53)
        if len(open_ports) > 0:
            return -1
        else: 
            return 1

def HTTPS_token_contains(url):
    # Analizar la URL para extraer el componente de dominio
    dominio = urlparse(url).netloc
    # Verificar si 'https' aparece en el dominio, no en el esquema
    if 'https' in dominio.lower():
        return -1
    else:
        return 1

def get_domain(url):
    """Extraer el dominio de una URL."""
    return urlparse(url).netloc

def classify_webpage_by_external_resources(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
    except requests.exceptions.ConnectionError:
        # Si hay un error de conexión, asume que podría ser phishing
        return -1
    except Exception as e:
        # Otros errores se pueden registrar o manejar de manera diferente
        return f"Error: {str(e)}"

    resources = soup.find_all(['img', 'script', 'link'], href=True) + soup.find_all(['img', 'script'], src=True)
    main_domain = get_domain(url)
    external_urls = 0
    total_urls = 0

    for resource in resources:
        src = resource.get('src') or resource.get('href')
        if src:
            resource_domain = get_domain(src)
            total_urls += 1
            if resource_domain and resource_domain != main_domain:
                external_urls += 1

    if total_urls == 0:
        return -1

    external_percentage = (external_urls / total_urls) * 100

    # Aplicando la regla basada en el porcentaje de recursos externos
    if external_percentage < 22:
        return 1
    elif 22 <= external_percentage <= 61:
        return 0
    else:
        return -1

def get_domain(url):
    """Helper function to extract the domain from a URL."""
    parsed_url = urlparse(url)
    if parsed_url.netloc:
        return parsed_url.netloc
    return None

def classify_webpage_by_anchor_urls(url):
    try:
        response = requests.get(url)
        domain = get_domain(url)
        soup = BeautifulSoup(response.content, 'html.parser')
    except requests.RequestException as e:
        return -1

    anchors = soup.find_all('a', href=True)
    if not anchors:
        return 1

    external_anchors = 0
    total_anchors = 0

    for anchor in anchors:
        href = anchor.get('href')
        # Ignore non-HTTP links like JavaScript, mailto, or anchor links
        if href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
            continue
        full_url = urljoin(url, href)  # Resolve relative URLs
        anchor_domain = get_domain(full_url)
        if anchor_domain and anchor_domain != domain:
            external_anchors += 1
        total_anchors += 1

    if total_anchors == 0:
        return 0

    external_percentage = (external_anchors / total_anchors) * 100

    if external_percentage < 31:
        return 1
    elif 31 <= external_percentage <= 67:
        return 0
    else:
        return -1

def classify_webpage_by_script_meta_link(url):
    try:
        response = requests.get(url)
        domain = get_domain(url)
        soup = BeautifulSoup(response.content, 'html.parser')
    except requests.RequestException as e:
        return 0

    # Encontrar todas las etiquetas <meta>, <script> y <link> con atributos URL
    tags = soup.find_all(['meta', 'script', 'link'])
    total_links = 0
    external_links = 0

    # Atributos que pueden contener URLs
    url_attributes = ['href', 'src', 'content']

    for tag in tags:
        for attribute in url_attributes:
            url = tag.get(attribute)
            if url:
                # Completar URLs relativas
                full_url = urljoin(url, urlparse(url).path)
                tag_domain = get_domain(full_url)
                if tag_domain and tag_domain != domain:
                    external_links += 1
                total_links += 1

    if total_links == 0:
        return 0

    external_percentage = (external_links / total_links) * 100

    # Aplicando la regla basada en el porcentaje de recursos externos
    if external_percentage < 17:
        return 1
    elif 17 <= external_percentage <= 81:
        return 0
    else:
        return -1
    
def classify_webpage_by_sfh(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
    except requests.RequestException as e:
        return 0

    forms = soup.find_all('form')
    if not forms:
        return 1
    
    main_domain = get_domain(url)
    for form in forms:
        action = form.get('action', '').strip()
        
        # Verificar si está vacío o es "about:blank"
        if action == "" or action == "about:blank":
            return -1

        # Resolver URL relativa a absoluta
        full_action_url = urljoin(url, action)
        action_domain = get_domain(full_action_url)

        # Verificar si la acción apunta a un dominio diferente
        if action_domain != main_domain:
            return 0

    return 1   

def classify_webpage_by_submission_method(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
    except requests.RequestException as e:
        return 0

    # Revisar acciones de formularios
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action', '').strip().lower()
        # Verificar si la acción usa mailto:
        if 'mailto:' in action:
            return -1

    # Revisar la función mail() en elementos de script - indicativo de manejo en línea de PHP o JavaScript
    scripts = soup.find_all('script')
    for script in scripts:
        if script.string and 'mail(' in script.string.lower():
            return -1

    return 1

def is_domain_in_url(url, expected_keywords):
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc
    # Remover prefijos y sufijos comunes
    base_domain = hostname.replace('www.', '').split('.')[0]  # Extracción simplista de la parte base del dominio
    
    # Verificar si alguna de las palabras clave esperadas está en el dominio
    for keyword in expected_keywords:
        if keyword.lower() in base_domain.lower():
            return 1
    return -1

def classify_webpage_by_redirects(url):
    try:
        # Permitir redirección y capturar la respuesta
        response = requests.get(url, allow_redirects=True)
        
        # Calcular el número de redirecciones
        num_redirects = len(response.history)
        
        # Aplicar la regla basada en el número de redirecciones
        if num_redirects <= 1:
            return 1
        elif 2 <= num_redirects < 4:
            return 0
        else:
            return -1
    except requests.RequestException as e:
        return 0

def classify_webpage_by_on_mouseover(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
    except requests.RequestException as e:
        return 0

    scripts = soup.find_all('script')
    if not scripts:
        return 1

    # Verificar eventos onMouseOver que alteran la barra de estado
    suspicious_phrases = ['window.status', 'status=']
    for script in scripts:
        if script.string:
            # Verificar si alguna frase sospechosa está en el contenido del script
            if any(phrase in script.string for phrase in suspicious_phrases):
                return -1

    # Verificar adicionalmente JavaScript en línea en atributos HTML
    tags_with_events = soup.find_all(onmouseover=True)
    for tag in tags_with_events:
        if any(phrase in tag['onmouseover'] for phrase in suspicious_phrases):
            return -1

    return 1

def right_click_disable(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
    except requests.RequestException as e:
        return 0

    scripts = soup.find_all('script')
    if not scripts:
        return -1

    # Verificar scripts que deshabilitan el clic derecho
    suspicious_phrases = ['event.button == 2', 'event.button==2', 'event.button===2']
    for script in scripts:
        if script.string:
            if any(phrase in script.string for phrase in suspicious_phrases):
                if 'preventDefault' in script.string or 'return false' in script.string:
                    return -1

    # Verificar también JavaScript en línea dentro de atributos HTML que deshabilitan el clic derecho
    tags_with_events = soup.find_all(oncontextmenu=True)
    for tag in tags_with_events:
        if 'preventDefault' in tag['oncontextmenu'] or 'return false' in tag['oncontextmenu']:
            return -1

    return 1

def popup_window_contains(url):
    driver = webdriver.Chrome()  # Especificar la ruta a chromedriver si es necesario
    driver.get(url)

    try:
        # Esperar a que los elementos se carguen y buscar ventanas emergentes por nombre de clase
        popups = driver.find_elements(By.CLASS_NAME, "popup-class")  # Método actualizado
        for popup in popups:
            text_inputs = popup.find_elements(By.CSS_SELECTOR, "input[type='text']")
            if text_inputs:
                return -1
            else: 
                return -1
    finally:
        driver.quit()

    return 1

def iframe_contains(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
    except requests.RequestException as e:
        return 0

    # Verificar iframes
    iframes = soup.find_all('iframe')
    if iframes:
        return -1
    else:
        return 1

def classify_webpage_by_domain_age(url):
    try:
        domain_info = whois.whois(url)
    except whois.parser.PywhoisError as e:
        return -1 #f"WHOIS data not found for {url}: {e}"
    except Exception as e:
        return -1 # f"Error fetching WHOIS data: {e}"

    try:
        creation_date = domain_info.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if isinstance(creation_date, str):
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
        
        current_date = datetime.now()
        domain_age = current_date - creation_date
        
        if domain_age >= timedelta(days=183):  # Aproximadamente 6 meses
            return 1
        else:
            return -1
    except TypeError as e:
        return -1 # f"Invalid or unknown format for creation date: {e}"
    except Exception as e:
        return -1 # f"Error processing domain age: {e}"

def classify_webpage_by_dns_record(url):
    try:
        # Intentar resolver el dominio a una dirección IP
        ip_address = socket.gethostbyname(url)
        return 1  # Si esto tiene éxito, el dominio tiene un registro DNS
    except socket.gaierror:
        return -1  # Si no se encuentra una dirección IP, podría ser un intento de phishing
    except Exception as e:
        return -1 #f"Error checking DNS record: {e}"
    
def get_website_rank(domain):
    if domain.endswith("/"):
        domain_aux = domain[:-1]
    else: 
        domain_aux = domain
    api_url = f"https://openpagerank.com/api/v1.0/getPageRank?domains[]={domain_aux}"
    api_key = '0o84gss4kkk008k88gko8wsg8gwcccc8kgk0wsgg' # --> usa la api de https://www.domcop.com/openpagerank/auth/signup para poder accer
    headers = {'API-OPR': api_key}
    response = requests.get(api_url, headers=headers)
    data = response.json()
    return data

def classify_webpage_by_traffic(domain):
    rank = get_website_rank(domain)
    rank_aux = rank['response'][0]['rank'] 
    if (rank_aux != '') and (rank_aux != None):
        rank_aux2 = int(rank_aux)
    else:
        rank_aux2 = None
    if rank_aux2 is None:
        return -1
    elif rank_aux2 < 100000:
        return 1
    else:
        return 0
    
def classify_webpage_by_pagerank(domain):
    rank = get_website_rank(domain)
    rank_aux = rank['response'][0]['page_rank_decimal'] 
    if (rank_aux != '') and (rank_aux != None):
        rank_aux2 = int(rank_aux)
    else:
        rank_aux2 = 0
    if rank_aux2 < 0.2:
        return -1
    else:
        return 1

def is_webpage_indexed_by_google(url):
    try:
        # Realizar una búsqueda en Google para la URL
        search_results = search(url)  # La función search devuelve un iterador
        # Verificar si la URL está en los primeros resultados de búsqueda
        for result in search_results:
            if url in result:
                return 1
        return -1
    except Exception as e:
        return -1 #f"Error during search: {e}"

def fetch_links(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        links = soup.find_all('a', href=True)  # Encontrar todos los hipervínculos en la página web
        external_links = [link['href'] for link in links if link['href'].startswith('http') and not link['href'].startswith(url)]
        return len(set(external_links))  # Usar set para contar enlaces únicos
    except requests.RequestException as e:
        print(f"Error fetching page: {e}")
        return None

def classify_webpage_by_links(url):
    number_of_links = fetch_links(url)
    if number_of_links is None:
        return 0 #"Error in fetching links"
    
    if number_of_links == 0:
        return -1
    elif 0 < number_of_links <= 2:
        return 0
    else:
        return 1

def is_phishing_site(url):
    user_id = 'defran'
    api_key = 'CEFpgr1PafaRzyrHJwnvV9RuK1JXkaPI6yHZnpJfhkzWqACp'
    # Extraer el dominio de la URL
    domain = urlparse(url).netloc
    
    # Resolver IP y verificar contra IPs de phishing top
    try:
        ip_address = socket.gethostbyname(domain)
        params = {
            'user-id': user_id,
            'api-key': api_key,
            'ip': ip_address
        }
    except socket.gaierror:
        # Si la resolución DNS falla, manejar adecuadamente
        print("DNS resolution failed.")
        return -1
    
    try:
        # Realizar la solicitud a la API
        response = requests.get(url, params=params)
        response.raise_for_status()  # Lanza un error para códigos de estado HTTP 4xx/5xx

        # Procesar la respuesta
        data = response.json()
        if data.get('is-listed'):
            return -1
        else:
            return 1
    except requests.exceptions.RequestException as e:
        print(f"Error en la solicitud: {e}")
        return -1
    except ValueError:
        print("Error al analizar la respuesta JSON.")
        return -1


if __name__ == "__main__":
    #LOGO EN ASCII  
    result = []
    image_path = "logo.jpeg"
    ascii_logo = logo(image_path, output_width=70)
    print(ascii_logo) if isinstance(ascii_logo, str) else print("Error converting image.")
    ###############################################################################
    url = input("introduzca una url: ")
    ########################IP EN LA URL########################################### --> http://125.98.3.123/fake.html
    having_IPhaving_IP_Address = having_IP(url)
    result.append(having_IPhaving_IP_Address)
    #######################LONGITUD DE LA URL###################################### --> http://federmacedoadv.com.br/3f/aze/ab51e2e319e51502f416dbe46b773a5e/?cmd=_home&amp;dispatch=11004d58f5b74f8dc1e7c2e8dd4105e811004d58f5b74f8dc1e7c2e8dd4105e8@phishing.website.html
    URLURL_Length = lenght_URL(url)
    result.append(URLURL_Length)
    #######################URL ACORTADA############################################ --> http://portal.hud.ac.uk/ --> tiny url
    Shortining_Service = tiny_URL(url)#revisar ya que http://www.paypal.com/ sale como que esta acortada por la redirección  
    result.append(Shortining_Service)
    ######################ARROBA EN LA URL######################################### --> @ en la URL
    having_At_Symbol = having_arroba(url)
    result.append(having_At_Symbol)
    ######################DOBLE BARRA EN LA URL#################################### --> http://www.legitimate.com//http://www.phishing.com
    double_slash_redirecting = is_doubleslash_url(url)   
    result.append(double_slash_redirecting) 
    #####################PREFIJOS Y SUFIJOS######################################## --> http://www.confirme-paypal.com/
    Prefix_Suffix = contains_prefix_sufix(url)
    result.append(Prefix_Suffix)
    #####################CONTIENE UN SUBDOMINIO#################################### --> http://www.hud.ac.uk/students/
    having_Sub_Domain = contains_subdomains(url)
    result.append(having_Sub_Domain)
    #####################CONTIENE CERTIFICADO SSL################################## --> en funcion del tiempo del certificado de si lo encuentra o no
    SSLfinal_State = contains_SSL(url)#funciona regulero con las legitimas
    result.append(SSLfinal_State)
    #####################LONGITUD DE DOMAIN REGISTRATION########################### --> cuanto le queda para expirar
    Domain_registeration_length = domain_expiration(url) #no lo pilla bien seguro vamos
    result.append(Domain_registeration_length)
    #####################FAVICON CONATINS########################################## --> si el favicon esta asociado a una pagina web legítima
    favicon = favicon_contains(url)
    result.append(favicon)
    #####################CONTIENE PUERTO############################################ --> revisa los puertos que tiene abiertos por si hay alguno que no este bien
    port = classify_by_ports(url) #da un error de la resulucion DNS si no existe el dominio y se queda pillada creo
    #revisar la API de NMAP 
    result.append(port)########################################################################################### CORREGIR
    #####################EXITENCIA DEL HTTPS EN EL DOMINIO########################## --> que use https en el servidor
    HTTPS_token = HTTPS_token_contains(url)
    result.append(HTTPS_token)
    #####################CONTIENE OBJETOS DE OTROS DOMINIOS######################### --> contiene recursos externos como imagenes, videos...
    requests_URL = classify_webpage_by_external_resources(url)
    result.append(requests_URL)
    #####################CONTIENE LA ETIQUETA A##################################### --> contiene la etiqueta <a> muchas veces
    URL_of_Anchor = classify_webpage_by_anchor_urls(url) #trata como phishing la de wikipedia, pero esta bien
    result.append(URL_of_Anchor)
    #####################CONTIENE LINKS META LINK Y SCRIPT########################## --> contiene las etiquetas meta, link y script en un porcentaje muy alto
    Link_in_Tags = classify_webpage_by_script_meta_link(url)
    result.append(Link_in_Tags)
    #####################SFH es igual a about:blank################################# -->  SFH se refiere a "Server Form Handler",  los atacantes a menudo crean formularios que parecen legítimos pero envían información a servidores maliciosos. Un SFH que apunta a un dominio externo sospechoso o a about:blank
    SFH_contains  = classify_webpage_by_sfh(url)
    result.append(SFH_contains)
    #####################Redireccionar la información a su email personal########### --> redirige la información de la victima con mail() a su email personal
    Submiting_to_email = classify_webpage_by_submission_method(url)
    result.append(Submiting_to_email)
    #####################COMPROBAR SI EL HOSTSNAME ESTA EN LA URL################### --> revisa el nombre del host y comprueba que sea la URL le contenga
    Abnormal_URL = is_domain_in_url(url, ['google']) # este hay q pulirlo aun mas y revisarlo
    result.append(Abnormal_URL)
    #####################NUMERO DE VECES QUE SE HA REDIRIGIDO LA WEB################ --> comprueba que la web no haya sido redirigida mas de 1 vez, pero es rarete
    redirect_contains = classify_webpage_by_redirects(url)
    result.append(redirect_contains)
    #####################evento onMouseEvent######################################## --> comprueba que no haya cambios en la status bar para que no se realicen cambios
    on_mouseover = classify_webpage_by_on_mouseover(url)
    result.append(on_mouseover)
    #####################inhabilitar el click derecho############################### --> inhabilitar el click derecho para que no se pueda inspeccionar el codigo fuente de la pagina
    rightClick = right_click_disable(url)
    result.append(rightClick)
    #####################contiene un popup########################################## --> contiene un poupup para ingresar sus datos --> hace un prompt q no me mola mucho pero bueno
    popUpWindow = popup_window_contains(url)
    result.append(popUpWindow)
    #####################si contiene algun iframe################################### --> muestra una pagina pero realmente estas hacinedo clicks en otra
    iframe = iframe_contains(url)
    result.append(iframe)
    #####################edad del dominio########################################### --> si el dominio tiene mas de 6 meses entonces es legítimo
    age_of_domain = classify_webpage_by_domain_age(url)
    result.append(age_of_domain)
    #####################DNS record################################################# --> comprobar el registro del DNS a ver si esta vacio
    DNS_record = classify_webpage_by_dns_record(url) # --> funciona rarete
    result.append(DNS_record)
    #####################Numero de visitantes####################################### --> comprueba si el numero de visitantes es superior o inferior a 100.000
    website_traffic = classify_webpage_by_traffic(url) # --> mno punciona bien, las marca todas como phishing
    result.append(website_traffic)
    ####################Como de importante es la pagina en internet################# --> comprueba si el valor del rango de la pagina es menor que 0.2
    pageRank = classify_webpage_by_pagerank(url)
    result.append(pageRank)
    ####################GOOGLE INDEX############################################### --> comprueba que la página tiene un indice en google
    google_index = is_webpage_indexed_by_google(url)
    result.append(google_index)
    ###################NUMERO DE LINKS APUNTANDO################################## --> numero de links apuntando a una pagina
    links_pointing = classify_webpage_by_links(url)
    result.append(links_pointing)
    ###################TOP PHISHING IPS########################################### --> la ip pertenece al top de ips de phishing
    top_ips_phishing = is_phishing_site(url)
    result.append(top_ips_phishing)
    print(result)
    
    ######################################################################################################################################
    ######################################################################################################################################
    ######################################################################################################################################
    ######################################################################################################################################
    ################################################RED NEURONAL ENTRENANDO Y PREDICIENDO#################################################
    ######################################################################################################################################
    ######################################################################################################################################
    ######################################################################################################################################
    df = pd.read_csv("C:\\Users\\jezequiel\\Documents\\Universidad\\Segundo cuatri\\TFG\\pytorch_project\\dataset\\dataset.csv")

    # Elimina la columna index ya que no la va a usar
    df = df.drop(columns=['index']) 

    # una función diseñada para evaluar el rendimiento de un modelo de clasificación binaria.
    #
    # --> Matriz de confusión: Esta es una tabla que muestra el número de verdaderos positivos, verdaderos negativos, falsos positivos y falsos negativos. Ayuda a entender cómo se están clasificando las muestras por el modelo.
    # --> Puntuación de precisión (Accuracy score): Esta es una métrica que calcula la proporción de muestras clasificadas correctamente por el modelo sobre el total de muestras. Se calcula como (verdaderos positivos + verdaderos negativos) / (verdaderos positivos + verdaderos negativos + falsos positivos + falsos negativos).
    # --> Reporte de clasificación (Classification report): Esta es una descripción detallada del rendimiento del modelo que incluye precision, recall, f1-score y support para cada clase, así como la precisión global, la exhaustividad y el f1-score promedio.
    #
    def binary_classification_accuracy(actual, pred):
        
        print(f'Confusion matrix: \n{confusion_matrix(actual, pred)}')
        print(f'Accuracy score: \n{accuracy_score(actual, pred)}')
        print(f'Classification report: \n{classification_report(actual, pred)}')


    # Convertir -1 a 0 en la columna 'Result' del DataFrame
    df['Result'] = np.where(df['Result'] == -1, 0, df['Result'])

    # Definir la variable objetivo (target) y las características (features)
    target = df['Result']
    features = df.drop(columns=['Result'])

    # Definir el número de divisiones y la semilla aleatoria para la validación cruzada
    folds = KFold(n_splits=4, shuffle=True, random_state=42)

    # Inicializar listas para almacenar índices de entrenamiento y validación
    train_index_list = list()
    validation_index_list = list()
    
    # Iterar sobre las divisiones de validación cruzada
    for fold, (train_idx, validation_idx) in enumerate(folds.split(features, target)):
    
        # Inicializar el modelo de clasificación (XGBoost)
        model = XGBClassifier()
        
        # Entrenar el modelo con los datos de entrenamiento de esta división
        model.fit(np.array(features)[train_idx,:], np.array(target)[train_idx])

         # Realizar predicciones en los datos de validación de esta división
        predicted_values = model.predict(np.array(features)[validation_idx,:])
        
        # Imprimir el rendimiento del modelo para esta división
        print(f'==== FOLD {fold+1} ====')
        binary_classification_accuracy(np.array(target)[validation_idx], predicted_values)
    
    datos_prediccion = torch.Tensor(result).unsqueeze(0)
    print(datos_prediccion)
    prediccion = model.predict(datos_prediccion)
    print("Prediccion: ", prediccion)

    