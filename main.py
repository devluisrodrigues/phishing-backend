from fastapi import FastAPI, Query
from utils import get_all_domain_info
from urllib.parse import unquote


app = FastAPI()

"""FastAPI application for handling the logic of a Phishing Detection System.
This application provides an endpoint to check if a given URL is phishing or not.

The process of checking a URL involves the following steps:
1. **URL Preprocessing**: The URL is preprocessed to extract relevant features.
2. **Analyze metadata**: The metadata of the URL is analyzed, this process checks how old the domain is,
DNS records, WHOIS records, and SSL certificate information.
3. **Machine Learning Model**: The preprocessed URL is passed to a machine learning model for prediction.
4. **Prediction**: The model returns a prediction indicating whether the URL is phishing or not.
"""

@app.get("/")
def read_root():
    return {"message": "Welcome to the Phishing Detection System API. Use /predict endpoint to check a URL."}

@app.get("/predict/")
def predict(url: str):
    """
    Predict if the given URL is phishing or not.
    :param url: The URL to be checked.
    :return: A Score indicating how likely the URL can be trustuble or not.
    """
    
    # Preprocess the URL
    url = url.lower()
    url = url.replace("http://", "").replace("https://", "")
    url = url.replace("www.", "")
    url = url.split("/")[0]
    
    # Analyze metadata
    domain_info = get_all_domain_info(url)
    if domain_info is None:
        return {"error": "Failed to retrieve domain information."}
    
    return domain_info


@app.get("/check-domains/")
def check_domains(domains: str = Query(...), severity: int = Query(default=1)):
    """
    Check the age of multiple domains if they haven't been analyzed yet.
    :param domain: List of domain names as query parameters.
    :return: A JSON object with the age of each domain and whether it was newly analyzed.
    """
    results = {}
    
    print(f"\n\nSeverity: {severity}\n\n")
        
    domains = domains.split(",")
                    
    for domain in domains:
        if domain:
            domain = unquote(domain)
            domain = domain.strip()
            domain = domain.lower()
            domain = domain.replace("http://", "").replace("https://", "")
            domain = domain.replace("www.", "")
            domain = domain.split("/")[0]
            
        # If domain has already been analyzed, skip it
        if domain in results:
            print(f"Dominio {domain} has already been analyzed")
            continue
        else:
            try:
                print(f"Checking domain: {domain}")
            
                # Get domain information
                is_phising = get_all_domain_info(domain,severity)
                
                # Store result for this specific domain
                results[domain] = is_phising
            except Exception as e:
                # print(f"Error processing domain {domain}: {str(e)}")
                results[domain] = {"error": str(e)}
                
    print(f"Results: {results}")

    return results