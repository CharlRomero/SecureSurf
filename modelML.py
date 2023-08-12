#Librerías para importar datos
from ipwhois import IPWhois 
import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
from datetime import datetime
import time
from dateutil.parser import parse as date_parse

def recolectar_datos_sitioweb(url):
    data_set_siteweb = []
    try:
        ipaddress.ip_address(url)
        data_set_siteweb.append(-1)
    except:
        data_set_siteweb.append(1)

    if len(url) < 54:
        data_set_siteweb.append(1)
    elif len(url) >= 54 and len(url) <= 75:
        data_set_siteweb.append(0)
    else:
        data_set_siteweb.append(-1)