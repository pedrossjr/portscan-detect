#################################################################################
# Autor: Pedro Silva                                                            #
#                                                                               #
# Data: 01/10/2024                                                              #
#                                                                               # 
# Descrição: Este projeto irá monitorar o tráfego de rede e detectar tentativas #
#            de port scanning. O código usa a biblioteca Scapy para capturar    #
#            pacotes de rede e identificar padrões suspeitos, como múltiplas    #
#            tentativas de conexão a diferentes portas em um curto intervalo    #
#            de tempo.                                                          #
#                                                                               #
#################################################################################

import os
import logging
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from scapy.all import *
from scapy.all import sniff
from collections import defaultdict
from dotenv import load_dotenv
import platform

# Verifica Sistema Operacional
sistema_operacional = platform.system()

# Carrega as variáveis de ambiente do arquivo .env
load_dotenv()

# Realiza a limpeza do prompt
os.system('cls')

# Definição de cores das variáveis.
AMARELO="\033[93m"
BRANCO="\033[97m"
CIANO='\033[96m'
VERDE="\033[92m"
ROXO="\033[91m"
MAGENTA="\033[95m"
RESET='\033[0m'

# Definindo a janela de tempo para detectar múltiplas tentativas de conexão
TIME_WINDOW = 10 # segundos
THRESHOLD = 10   # número de portas diferentes em um curto período

# Lista de IPs a serem ignorados
ips_ignorados = ['192.168.3.176']

# Configura o arquivo de log
logging.basicConfig(filename='port_scan_logs.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

# Armazena as tentativas de conexão
scan_attempts = defaultdict(list)

# Função para processar cada pacote capturado
def detect_port_scan(pkt):
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        
        # Verifica se o IP está na lista de IPs ignorados
        if src_ip in ips_ignorados:
            print(f"Pacote de {src_ip} ignorado.")
            return
    
        dst_port = pkt[TCP].dport
        current_time = time.time()

        # Armazenar a tentativa de conexão (IP de origem e porta de destino)
        scan_attempts[src_ip].append((dst_port, current_time))

        # Filtrar as tentativas que ocorreram nos últimos X segundos (janela de tempo)
        scan_attempts[src_ip] = [(port, t) for port, t in scan_attempts[src_ip] if current_time - t < TIME_WINDOW]

        # Verificar se o número de tentativas excede o limite
        if len(scan_attempts[src_ip]) > THRESHOLD:
            # Loop para detectar port scan por IP
            for ip, attempts in scan_attempts.items():
                ultimo_ip = None # Armazena o último IP visto
                ultima_porta = None  # Armazena a última porta vista
                portas_unicas = []   # Lista para armazenar as portas únicas

                for port, t in attempts:
                    if ip != ultimo_ip and port != ultima_porta:
                        portas_unicas.append(port)
                        ultimo_ip = ip
                        ultima_porta = port

                        # Imprimir cada detecção de port scan no terminal
                        log_message_termnal = CIANO + f"Possivel port scan detectado do IP externo: " + RESET
                        log_message_termnal += f"{ip} - "
                        log_message_termnal += VERDE + "Porta: " + RESET
                        log_message_termnal += f"{port}"

                        # Escreve cada detecção de port scan no arquivo de log
                        log_message = f"Possivel port scan detectado do IP externo {ip} na porta: {port}"

                        print(log_message_termnal)
                        logging.info(log_message)
                        enviar_email_alerta(src_ip, [port for port, t in scan_attempts[src_ip]])  # Envia alerta por e-mail

# Função para enviar o e-mail de alerta
def enviar_email_alerta(ip_suspeito, portas):
    sender_email = os.getenv("EMAIL_REMETENTE")
    receiver_email = os.getenv("EMAIL_DESTINATARIO")
    password = os.getenv("EMAIL_SENHA_REMETENTE")
    smtp_ssl = os.getenv("EMAIL_SMTP_SSL")
    port_mail = os.getenv("EMAIL_PORTA")

    # Configurando o e-mail
    message = MIMEMultipart("alternative")
    message["Subject"] = "Alerta de Segurança: Possível Port Scan Detectado!"
    message["From"] = sender_email
    message["To"] = receiver_email

    # Corpo do e-mail
    text = f"""
    Alerta de Port Scan:
    IP suspeito: {ip_suspeito}
    Portas: {portas}
    """
    part = MIMEText(text, "plain")
    message.attach(part)

    # Enviando o e-mail
    with smtplib.SMTP_SSL(smtp_ssl, port_mail) as server:
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message.as_string())
    print(f"Alerta enviado para {receiver_email}")

# Bloqueia ping de entrada para o IP suspeito dependendo do sistema operacional
# Utiliza o firewall do Windows para bloquear o endereço IP via linha de comando
# Utiliza o IP tables para Linux para bloquear o endereço IP via terminal
def bloquear_ip(ip_suspeito, sistema_operacional):
    if sistema_operacional == "Windows":
        comando = f"netsh advfirewall firewall add rule name='BLOCK IP ADDRESS - {ip_suspeito}' dir=in action=block remoteip=10.10.10.10"
    elif sistema_operacional == "Linux":
        comando = f"sudo iptables -A INPUT -s {ip_suspeito} -j DROP"
    
    comando = f"sudo iptables -A INPUT -s {ip_suspeito} -j DROP"
    os.system(comando)
    print(f"IP {ip_suspeito} bloqueado.")

def cabecalho():
    print(ROXO + titulo + RESET)
    print(divider)

titulo = """

██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗    ██████╗ ███████╗████████╗███████╗ ██████╗████████╗
██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║    ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║     ███████║██╔██╗ ██║    ██║  ██║█████╗     ██║   █████╗  ██║        ██║   
██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║    ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   
██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║    ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   
╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝    ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝   

V.1.0

Monitorar o tráfego de rede e detectar tentativas de port scanning.                                            Pedro Silva"""

divider = """------------------------------------------------------------------------------------------------------------------------------"""

# Mostrar cabeçalho
cabecalho()

# Entrada de dados para o tempo em minutos
tempo_em_minutos = int(input("Por quantos minutos o scanner ficará em execução? "))

# Converte minutos para segundos
tempo_em_segundos = tempo_em_minutos * 60

# Capturando pacotes na interface de rede (ex: 'eth0' no Linux ou 'Wi-Fi' no Windows)
print("Monitorando tentativas de port scan...")
sniff(filter="tcp", prn=detect_port_scan, timeout=tempo_em_segundos)

print("Scanner finalizado.")