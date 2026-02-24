import keyring
import requests
import sys

whaccess = keyring.get_password("urlchecker", "whalebone_apiaccesskey")
whsecret = keyring.get_password("urlchecker", "whalebone_apisecretkey")

def check_url(domain):
    headers = {
        'accept': 'application/json',
        'Wb-Access-Key': whaccess,
        'Wb-Secret-Key': whsecret,
    }

    params = {
        'fqdn': domain,
    }

    response = requests.get('https://api.cloud.joindns4.eu/whalebone/2/domain/analysis', params=params, headers=headers)
    return response.json()

def is_domain(domain):
    if domain.startswith("http"):
        return "This is not a domain"
    elif domain.__contains__("/"):
        return "This is not a domain"
    else:
        return check_url(domain)

print(is_domain(sys.argv[1]))

"""
Expected threat_type results

Enum: [ porn, gambling, audio-video, advertisement, games, drugs, weapons,
social-networks, tracking, racism, fakenews, violence, chat, terrorism,
coinminer, p2p, doh, child-abuse ]
"""
