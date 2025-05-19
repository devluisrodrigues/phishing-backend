# Auxiliar functions for the main phishing detection script

import whois
import datetime
import ssl
import socket
import nltk
import tldextract
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

from settings import DOMAIN_AGE_THRESHOLD, THRESHOLD_SUBDOMAINS, LEVENSHTEIN_THRESHOLD, REDIRECT_THRESHOLD

from settings import SCORE_DOMAIN_AGE, SCORE_VALID_SSL_CERTIFICATE, SCORE_SPECIAL_CHARACTERS, SCORE_SUBDOMAINS, SCORE_IP_ADDRESS, SCORE_DYNAMIC_DNS, SCORE_SIMILAR_TO_OTHER_DOMAIN, SCORE_REDIRECTS, SCORE_SENSITIVE_FORMS, SCORE_MAX_THRESHOLD


# Main function to get all domain information
def get_all_domain_info(domain):
    """
    Get all information for a domain.
    This function gets the domain age, DNS records, WHOIS information, and SSL certificate information.
    
    :param domain: The domain name.
    :return: A dictionary with all information.
    """
    # Get WHOIS data once
    whois_data = get_whois_data(domain)
    
    # print(f"WHOIS data for {domain}: {whois_data}")
    
    domain_info = {}
    
    #Levelshtin distance
    domain_info["similar_to_well_known_domain"] = similar_to_well_known_domain(domain)
    if domain_info["similar_to_well_known_domain"]:
        return True
    
    # Whois data
    domain_age = get_domain_age(whois_data)
    domain_info["check_domain_age"] = True if domain_age and domain_age > DOMAIN_AGE_THRESHOLD else False
    domain_info["dns_records"] = get_dns_records(whois_data)
    domain_info["whois_info"] = get_whois_info(whois_data)
    
    # SSL data
    ssl_info = get_ssl_info(domain)
    domain_info["valid_ssl"] = check_if_ssl_valid(ssl_info)
    
    # General domain information
    domain_info["has_special_characters"] = has_especial_characters(domain)
    domain_info["has_many_subdomains"] = has_many_subdomains(domain)
    domain_info["is_ip_address"] = is_ip_address(domain)
    domain_info["has_dynamic_dns"] = has_dynamic_dns(domain)
    
    # Need requests:
    url = f"http://{domain}"
    success, response = make_request(url)
    
    if success:
        # Check for suspicious redirects
        suspicious_redirect, redirect_details = is_suspicious_redirect(response, url, REDIRECT_THRESHOLD)
        domain_info["suspicious_redirect"] = suspicious_redirect
        domain_info["redirect_details"] = redirect_details
        
        # Analyze HTML for sensitive forms
        suspicious_form, form_details = analise_basica_html(response)
        domain_info["suspicious_form"] = suspicious_form
        domain_info["form_details"] = form_details
    else:
        domain_info["suspicious_redirect"] = False
        domain_info["redirect_details"] = "Request failed"
        domain_info["suspicious_form"] = False
        domain_info["form_details"] = "Request failed"
        
    print(f"domain: {domain} and domain_info: {domain_info}")
        
    # Calculate score
    score = calculate_score(domain_info)
    
    return score >= SCORE_MAX_THRESHOLD

def calculate_score(domain_info):
    """
    Calculate the score based on the domain information.
    :param domain_info: Dictionary with domain information.
    :return: The calculated score.
    """
    score = 0
    
    # Domain age
    if domain_info["check_domain_age"]:
        score += SCORE_DOMAIN_AGE
    
    # SSL certificate
    if not domain_info["valid_ssl"]:
        score += SCORE_VALID_SSL_CERTIFICATE
    
    # Special characters
    if domain_info["has_special_characters"]:
        score += SCORE_SPECIAL_CHARACTERS
        
    # Subdomains
    if domain_info["has_many_subdomains"]:
        score += SCORE_SUBDOMAINS
        
    # IP address
    if domain_info["is_ip_address"]:
        score += SCORE_IP_ADDRESS
        
    # Dynamic DNS
    if domain_info["has_dynamic_dns"]:
        score += SCORE_DYNAMIC_DNS
        
    # Similar to well-known domains
    if domain_info["similar_to_well_known_domain"]:
        score += SCORE_SIMILAR_TO_OTHER_DOMAIN
        
    # Suspicious redirects
    if domain_info["suspicious_redirect"]:
        score += SCORE_REDIRECTS
        
    # Sensitive forms
    if domain_info["suspicious_form"]:
        score += SCORE_SENSITIVE_FORMS
    
    return score

# ============================================================================
# Getting WHOIS data
# ============================================================================
def get_whois_data(domain):
    """
    Get WHOIS data for a domain.
    :param domain: The domain name.
    :return: WHOIS object or None if there was an error.
    """
    try:
        return whois.whois(domain)
    except Exception as e:
        print(f"Error retrieving WHOIS data: {e}")
        return None

def get_domain_age(whois_data):
    """
    Calculate the age of a domain in days.
    :param whois_data: WHOIS data object.
    :return: The age of the domain in days.
    """
    try:
        if whois_data is None:
            return None
            
        creation_date = whois_data.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            return None
        age = (datetime.datetime.now() - creation_date).days
        return age
    except Exception as e:
        print(f"Error calculating domain age: {e}")
        return None
    
def get_dns_records(whois_data):
    """
    Get DNS records from WHOIS data.
    :param whois_data: WHOIS data object.
    :return: A dictionary with DNS records.
    """
    try:
        if whois_data is None:
            return None
            
        dns_records = {
            "A": whois_data.a if hasattr(whois_data, 'a') else None,
            "MX": whois_data.mx if hasattr(whois_data, 'mx') else None,
            "NS": whois_data.ns if hasattr(whois_data, 'ns') else None,
            "CNAME": whois_data.cname if hasattr(whois_data, 'cname') else None,
            "TXT": whois_data.txt if hasattr(whois_data, 'txt') else None
        }
        return dns_records
    except Exception as e:
        print(f"Error processing DNS records: {e}")
        return None
    
def get_whois_info(whois_data):
    """
    Extract WHOIS information.
    :param whois_data: WHOIS data object.
    :return: A dictionary with WHOIS information.
    """
    try:
        if whois_data is None:
            return None
            
        whois_info = {
            "domain_name": whois_data.domain_name,
            "creation_date": whois_data.creation_date,
            "expiration_date": whois_data.expiration_date,
            "updated_date": whois_data.updated_date,
            "name_servers": whois_data.name_servers,
            "emails": whois_data.emails if hasattr(whois_data, 'emails') else None
        }
        return whois_info
    except Exception as e:
        print(f"Error extracting WHOIS info: {e}")
        return None
    
# ============================================================================
# Getting SSL certificate information
# ============================================================================

def get_ssl_info(hostname, port=443):
    """Retrieves SSL certificate information from a given hostname and port.

    Args:
        hostname (str): The hostname of the website.
        port (int, optional): The port number. Defaults to 443 (HTTPS).

    Returns:
        dict: A dictionary containing SSL certificate information, or None if an error occurs.
    """
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_info = ssock.getpeercert()
    except (socket.gaierror, socket.timeout, ConnectionRefusedError, ssl.SSLError) as e:
        print(f"Error: Could not retrieve SSL information for {hostname}: {e}")
        return None
    
    # Check if the certificate is valid
    if cert_info:
        ssl_info = {
            "subject": dict(x[0] for x in cert_info["subject"]),
            "issuer": dict(x[0] for x in cert_info["issuer"]),
            "notBefore": cert_info["notBefore"],
            "notAfter": cert_info["notAfter"],
            "serialNumber": cert_info["serialNumber"],
            "version": cert_info["version"],
        }
    else:
        print(f"Error: No SSL certificate information found for {hostname}")
        return None
    
    return ssl_info

def check_if_ssl_valid(ssl_info):
    """Check if the SSL certificate is valid.
    Args:
        ssl_info (dict): The SSL certificate information.
    Returns:
        bool: True if the SSL certificate is valid, False otherwise."""
        
    try:
        if ssl_info is None:
            return False
        
        valid = False

        not_after = datetime.datetime.strptime(ssl_info["notAfter"], "%b %d %H:%M:%S %Y %Z")
        
        if not_after > datetime.datetime.now():
            valid = True

    except Exception as e:
        print(f"Error: Could not parse SSL certificate expiration date: {e}")
        valid = None
        
    return valid

# ============================================================================
# Analyzing the domain name
# ============================================================================
def has_especial_characters(domain):
    """
    Check if the domain name contains special characters.
    :param domain: The domain name.
    :return: True if the domain name contains special characters, False otherwise.
    """
    special_characters = "!@#$%^&*()_+-=[]{}|;':\",<>?/"
    return any(char in special_characters for char in domain)

def has_many_subdomains(domain):
    """
    Check if the domain name has many subdomains.
    :param domain: The domain name.
    :return: True if the domain name has many subdomains, False otherwise.
    """
    cleaned_domain = tldextract.extract(domain)
    subdomains = cleaned_domain.subdomain.split('.') if cleaned_domain.subdomain else []
    
    return len(subdomains) > THRESHOLD_SUBDOMAINS

def is_ip_address(domain):
    """
    Check if the domain name is an IP address.
    :param domain: The domain name.
    :return: True if the domain name is an IP address, False otherwise.
    """
    try:
        socket.inet_aton(domain)
        return True
    except socket.error:
        return False
    
def similar_to_well_known_domain(domain):
    """
    Check if the domain name is similar to a well-known domain.
    :param domain: The domain name.
    :return: True if the domain name is similar to a well-known domain, False otherwise.
    """
    # Import domain list from db/urls.txt
    with open("db/urls.txt", "r") as file:
        well_known_domains = file.read().splitlines()
        
    # clean the domain name:
    domain_parts = tldextract.extract(domain)
    domain_name = domain_parts.domain.lower()
    
    for known_domain in well_known_domains:
        known_domain_parts = tldextract.extract(known_domain)
        known_domain_name = known_domain_parts.domain.lower()
        
        # Se for igual, não é phishing
        if domain_name == known_domain_name:
            return False
        
        # Calculate the Levenshtein distance
        distance = nltk.edit_distance(domain_name, known_domain_name)
        if distance < LEVENSHTEIN_THRESHOLD:
            return True
        
        if known_domain_name.startswith(domain_name) or domain_name.startswith(known_domain_name):
            return True

        
    return False

# ============================================================================
# Other functions
# ============================================================================

# Verificação de uso de DNS dinâmico (ex: domínios no-ip, dyndns
def has_dynamic_dns(domain):
    """
    Verifica se o domínio utiliza DNS dinâmico (ex: no-ip, dyndns).
    :param domain: O nome de domínio completo.
    :return: True se for DNS dinâmico, False caso contrário.
    """
    with open("db/dynamic_dns.txt", "r") as file:
        dynamic_dns_domains = [line.strip().lower() for line in file if line.strip()]
    
    domain = domain.lower()

    for dyn_domain in dynamic_dns_domains:
        if domain == dyn_domain or domain.endswith("." + dyn_domain):
            return True
    return False

def make_request(url):
    """
    Faz uma requisição HTTP para a URL fornecida.
    :param url: URL completa a ser analisada.
    :return: (bool, resposta) -> False se a requisição falhar, e a resposta da requisição.
    """
    try:
        response = requests.get(url, timeout=5)
        return True, response
    except requests.RequestException as e:
        return False, str(e)

def is_suspicious_redirect(response, original_url, max_redirects=3):
    """
    Verifica se houve redirecionamentos suspeitos com base na resposta.
    :param response: Objeto `requests.Response`.
    :param original_url: URL original usada na requisição.
    :param max_redirects: Limite de redirecionamentos aceitável.
    :return: (bool, detalhes)
    """
    redirect_chain = response.history
    final_url = response.url

    if len(redirect_chain) > max_redirects:
        return True, f"Redirecionamentos excessivos ({len(redirect_chain)})"

    origem = tldextract.extract(original_url).domain
    destino = tldextract.extract(final_url).domain
    if origem != destino:
        return True, f"Redirecionamento de {origem} para {destino}"

    return False, "OK"


def analise_basica_html(response):
    """
    Analisa o HTML da resposta para detectar formulários de login ou campos sensíveis.
    :param response: Objeto `requests.Response`.
    :return: (bool, mensagem)
    """
    soup = BeautifulSoup(response.text, 'html.parser')

    forms = soup.find_all('form')
    for form in forms:
        inputs = form.find_all('input')
        for inp in inputs:
            tipo = (inp.get('type') or '').lower()
            nome = (inp.get('name') or '').lower()
            id_ = (inp.get('id') or '').lower()

            if tipo == "password":
                return True, "Formulário de login detectado (campo 'password')"
            if any(word in nome or word in id_ for word in ["login", "user", "email", "senha", "cpf", "card", "ssn", "security", "pin"]):
                return True, f"Campo sensível detectado: '{nome or id_}'"

    return False, "Nenhum formulário suspeito detectado"
