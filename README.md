![Logo](https://github.com/pedrossjr/portscan-detect/blob/main/my-app/img/portscan.png)

### Detector de Port Scanning com Python

#### Este projeto irá monitorar o tráfego de rede e detectar tentativas de port scanning. O código usa a biblioteca Scapy para capturar pacotes de rede e identificar padrões suspeitos, como múltiplas tentativas de conexão a diferentes portas em um curto intervalo de tempo.

### Instalação da biblioteca Scapy

#### Para utilização da biblioteca Scapy, utilize o comando conforme abaixo:

#### pedro@desktop:~$ pip install scapy

### Observação

#### Este scrpit foi executado em uma máquina Windows. 
#### Caso não tenha instalado em sua máquina, é preciso instalar o aplicativo Npcap.
#### Link para instalação do Npcap - https://npcap.com/dist/npcap-1.80.exe

### Uso do arquivo .env-template

#### O arquivo .env-template serve para configurar um serviço de e-mail para que o script possa enviar para o email os endereços dos IPs que estão nas tentativas de sniff na rede interna.

#### Para utilizá-lo, primeiro renonei-o de .env-template para .env e informe nas variáveis os valores do seu servidor do seu email.

### Execução

#### Para executar o script, faça conforme abaixo:

#### python portscan.py

#### O sistema perguntará por quantos minutos se deseja realizar a análise. Informe um número inteiro que representará a quantidade de minutos que o script será executado, após X minutos executando, o sistema exibirá a informação "Scanner finalizado".

### Observação para o envio de e-mail

#### Caso não queira enviar o e-mail da análise, apenas comente o código aproximadamente na linha 105 onde há a chamada da função enviar_email_alerta(src_ip, [port for port, t in scan_attempts[src_ip]])