# SpiderTrap Desktop

Aplicativo desktop em Python e PySide6 para diagnóstico básico de conectividade, monitoramento honeypot local e inspeção de portas em `127.0.0.1`.

## Requisitos

- Python 3.10 ou superior
- PySide6
- Comando `ping` disponível no sistema para o diagnóstico de rede

## Executar

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# Linux/macOS:
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

## O que o app faz

- **Rede**: identifica o IP local e executa quatro requisições ICMP para `8.8.8.8`.
- **Honeypot**: escuta conexões nas portas 21 (FTP), 22 (SSH) e 3389 (RDP), registrando IPs e horários.
- **Portas locais**: verifica portas selecionadas somente no endereço de loopback `127.0.0.1`.

## Atenção à segurança

O honeypot abre as portas configuradas em todas as interfaces de rede (`0.0.0.0`). Use apenas em equipamentos e redes que você administra ou tem autorização explícita para monitorar. Verifique as regras de firewall e a exposição do dispositivo antes de ativar. Portas abaixo de 1024 podem exigir privilégios elevados. O aplicativo é uma ferramenta didática/de diagnóstico e não substitui controles de segurança profissionais.

O teste de portas é limitado a `127.0.0.1`; ele não faz varredura de hosts externos.

## Empacotar para desktop

É possível gerar um executável com PyInstaller:

```bash
pip install pyinstaller
pyinstaller --noconfirm --windowed --name SpiderTrap main.py
```

O resultado fica em `dist/`. O empacotamento deve ser feito no sistema operacional de destino.

## Estrutura

- `main.py` — interface Qt e lógica local do aplicativo.
- `requirements.txt` — dependências Python.
