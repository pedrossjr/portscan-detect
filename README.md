# Detector de Port Scanning com Python

## Este projeto irá monitorar o tráfego de rede e detectar tentativas de port scanning. O código usa a biblioteca Scapy para capturar pacotes de rede e identificar padrões suspeitos, como múltiplas tentativas de conexão a diferentes portas em um curto intervalo de tempo.

# Instalação da biblioteca Scapy

## pip install scapy

# Observação

## Este scrpit foi executado em uma máquina Windows. 
## Caso não tenha instalado em sua máquina, é preciso instalar o aplicativo Npcap
## Link para instalação do Npcap - https://npcap.com/dist/npcap-1.80.exe

# Uso do arquivo .env-template

## O arquivo .env-template ser para configurar um serviço de e-mail para que o scrpt posso enviar para o email
## os endereços dos IPs que estão realizando tentativas de sniff na rede interna.

## Para utilizá-lo, primeiro reoneio de .env-template para .env e informe nas variáveis os valores do servidor do seu email.

