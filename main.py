import sys
import socket
import subprocess
import platform
import threading
from datetime import datetime

from PySide6.QtCore import Qt, Signal, QObject
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QPlainTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QFrame, QAbstractItemView
)

ALVO_PING = "8.8.8.8"
PORTAS_HONEYPOT = {21: "FTP", 22: "SSH", 3389: "RDP"}
PORTAS_AUDITORIA = {21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS",
                    3306: "MySQL", 3389: "RDP", 8080: "HTTP alternativo"}

COR_TEXTO = "#e6edf3"
COR_SUAVE = "#8b98a9"
COR_OK = "#5ad08a"
COR_ALERTA = "#ffb454"
COR_ERRO = "#ff6b6b"

ESTILO = """
QWidget {
    background-color: #0e1116;
    color: #d8dee9;
    font-family: "Segoe UI", "Inter", "Ubuntu", "Arial";
    font-size: 13px;
}
QLabel { background: transparent; }
QLabel#titulo { font-size: 24px; font-weight: 700; color: #e6edf3; }
QLabel#subtitulo { color: #8b98a9; }
QLabel#secao { font-size: 15px; font-weight: 600; color: #e6edf3; }
QLabel#ajuda { color: #8b98a9; }
QLabel#cardTitulo { color: #8b98a9; font-size: 12px; }
QLabel#cardValor { color: #e6edf3; font-size: 22px; font-weight: 700; }

QFrame#card {
    background-color: #151a21;
    border: 1px solid #262d38;
    border-radius: 10px;
}

QTabWidget::pane {
    border: none;
    border-left: 1px solid #262d38;
    padding-left: 18px;
}
QTabBar { background: #10151b; }
QTabBar::tab {
    background: transparent;
    color: #8b98a9;
    min-width: 148px;
    text-align: left;
    padding: 13px 16px;
    margin: 2px 8px 2px 0;
    border: none;
    border-left: 2px solid transparent;
    border-radius: 5px;
    font-weight: 600;
}
QTabBar::tab:selected { color: #e6edf3; background: #18221f; border-left: 2px solid #55ad96; }
QTabBar::tab:hover:!selected { color: #d8dee9; background: #151b21; }

QPushButton {
    background-color: #327f70;
    color: #ffffff;
    border: 1px solid #469987;
    border-radius: 8px;
    padding: 10px 22px;
    font-weight: 600;
}
QPushButton:hover { background-color: #3b9582; }
QPushButton:pressed { background-color: #286b5e; }
QPushButton:disabled {
    background-color: #1b212a;
    color: #5b6675;
    border: 1px solid #262d38;
}
QPushButton[perigo="true"] { background-color: #d6453d; border: 1px solid #ff6b6b; }
QPushButton[perigo="true"]:hover { background-color: #ea5a52; }
QPushButton[perigo="true"]:disabled {
    background-color: #1b212a;
    color: #5b6675;
    border: 1px solid #262d38;
}
QPushButton#secundario {
    background-color: #1b212a;
    color: #d8dee9;
    border: 1px solid #2f3846;
}
QPushButton#secundario:hover { background-color: #252d39; }
QPushButton#secundario:disabled { color: #5b6675; }

QPlainTextEdit {
    background-color: #0a0d12;
    border: 1px solid #262d38;
    border-radius: 10px;
    padding: 12px;
    color: #9be9b0;
    font-family: "Cascadia Mono", "Consolas", "DejaVu Sans Mono", "Courier New";
    font-size: 12px;
}

QTableWidget {
    background-color: #0e1116;
    alternate-background-color: #121720;
    border: 1px solid #262d38;
    border-radius: 10px;
    gridline-color: transparent;
    outline: none;
}
QTableWidget::item { padding: 6px 10px; border: none; }
QTableWidget::item:selected { background-color: #1c2736; color: #e6edf3; }
QHeaderView::section {
    background-color: #151a21;
    color: #8b98a9;
    border: none;
    border-bottom: 1px solid #262d38;
    padding: 10px;
    font-weight: 600;
}
QTableCornerButton::section { background-color: #151a21; border: none; }

QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: #2f3846; border-radius: 4px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #3d4859; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 2px; }
QScrollBar::handle:horizontal { background: #2f3846; border-radius: 4px; min-width: 30px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

QStatusBar { background-color: #0a0d12; color: #8b98a9; border-top: 1px solid #262d38; }
QStatusBar::item { border: none; }
"""


class Sinais(QObject):
    ping_pronto = Signal(str, str, bool)
    alerta = Signal(int, str, int)
    estado_porta = Signal(int, str, str)
    auditoria_pronta = Signal(list)


sinais = Sinais()


def obter_ip_local():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((ALVO_PING, 80))
        ip_local = s.getsockname()[0]
        s.close()
        return ip_local
    except Exception:
        return "127.0.0.1"


def testar_rede():
    ip_local = obter_ip_local()
    parametro = "-n" if platform.system().lower() == "windows" else "-c"
    comando = ["ping", parametro, "4", ALVO_PING]

    flags = 0
    if platform.system().lower() == "windows":
        flags = subprocess.CREATE_NO_WINDOW

    try:
        resultado = subprocess.run(comando, capture_output=True, text=True,
                                   errors="replace", timeout=20,
                                   creationflags=flags)
        saida = resultado.stdout or resultado.stderr
        ok = resultado.returncode == 0
    except subprocess.TimeoutExpired:
        saida = "O ping demorou demais e foi cancelado."
        ok = False
    except FileNotFoundError:
        saida = "Comando ping nao encontrado neste sistema."
        ok = False

    sinais.ping_pronto.emit(ip_local, saida, ok)


def armadilha(porta, parar):
    host = "0.0.0.0"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        s.bind((host, porta))
        s.listen(5)
        s.settimeout(1)
        sinais.estado_porta.emit(porta, "armada", "")

        ip_proprio = obter_ip_local()

        while not parar.is_set():
            try:
                conn, addr = s.accept()
            except socket.timeout:
                continue

            ip_atacante = addr[0]
            porta_origem = addr[1]

            if ip_atacante in ("127.0.0.1", "::1", ip_proprio):
                conn.close()
                continue

            sinais.alerta.emit(porta, ip_atacante, porta_origem)
            conn.send(b"Acesso negado.\n")
            conn.close()
    except Exception as e:
        sinais.estado_porta.emit(porta, "erro", str(e))
    finally:
        s.close()
        sinais.estado_porta.emit(porta, "parada", "")


def auditar_portas():
    alvo = "127.0.0.1"
    resultados = []

    for porta in PORTAS_AUDITORIA:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        status = s.connect_ex((alvo, porta))
        s.close()
        resultados.append((porta, status == 0))

    sinais.auditoria_pronta.emit(resultados)


def criar_card(titulo, valor):
    card = QFrame()
    card.setObjectName("card")
    layout = QVBoxLayout(card)
    layout.setContentsMargins(18, 14, 18, 14)
    layout.setSpacing(4)

    lbl_titulo = QLabel(titulo)
    lbl_titulo.setObjectName("cardTitulo")
    lbl_valor = QLabel(valor)
    lbl_valor.setObjectName("cardValor")

    layout.addWidget(lbl_titulo)
    layout.addWidget(lbl_valor)
    return card, lbl_valor


def pintar(label, cor):
    label.setStyleSheet(f"color: {cor};")


def criar_tabela(colunas):
    tabela = QTableWidget(0, len(colunas))
    tabela.setHorizontalHeaderLabels(colunas)
    tabela.verticalHeader().setVisible(False)
    tabela.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
    tabela.setEditTriggers(QAbstractItemView.NoEditTriggers)
    tabela.setSelectionBehavior(QAbstractItemView.SelectRows)
    tabela.setAlternatingRowColors(True)
    tabela.setShowGrid(False)
    tabela.setFocusPolicy(Qt.NoFocus)
    tabela.verticalHeader().setDefaultSectionSize(38)
    return tabela


def criar_item(texto, cor=None, centro=False):
    item = QTableWidgetItem(texto)
    if cor:
        item.setForeground(QColor(cor))
    if centro:
        item.setTextAlignment(Qt.AlignCenter)
    return item


def trocar_perigo(botao, ativo):
    botao.setProperty("perigo", ativo)
    botao.style().unpolish(botao)
    botao.style().polish(botao)


class Janela(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SpiderTrap Desktop")
        self.resize(1080, 740)
        self.setMinimumSize(900, 640)

        self.parar = threading.Event()
        self.ativas = 0
        self.erros = set()
        self.total_alertas = 0

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(24, 22, 24, 10)
        layout.setSpacing(14)

        titulo = QLabel("SpiderTrap Desktop")
        titulo.setObjectName("titulo")
        subtitulo = QLabel("Ferramentas locais de rede, monitoramento e auditoria de portas")
        subtitulo.setObjectName("subtitulo")
        layout.addWidget(titulo)
        layout.addWidget(subtitulo)

        self.abas = QTabWidget()
        self.abas.setTabPosition(QTabWidget.West)
        self.abas.setDocumentMode(True)
        self.abas.addTab(self.criar_aba_rede(), "Rede")
        self.abas.addTab(self.criar_aba_honeypot(), "Honeypot")
        self.abas.addTab(self.criar_aba_auditoria(), "Portas locais")
        layout.addWidget(self.abas)

        self.statusBar().showMessage("Pronto.")

        sinais.ping_pronto.connect(self.ping_finalizado)
        sinais.alerta.connect(self.registrar_alerta)
        sinais.estado_porta.connect(self.atualizar_porta)
        sinais.auditoria_pronta.connect(self.auditoria_finalizada)

    def criar_aba_rede(self):
        aba = QWidget()
        layout = QVBoxLayout(aba)
        layout.setContentsMargins(0, 20, 0, 12)
        layout.setSpacing(16)

        cards = QHBoxLayout()
        cards.setSpacing(14)
        card_ip, self.lbl_ip = criar_card("IP local", "—")
        card_alvo, _ = criar_card("Destino do ping", ALVO_PING)
        card_status, self.lbl_status_rede = criar_card("Conexão", "Não testada")
        cards.addWidget(card_ip)
        cards.addWidget(card_alvo)
        cards.addWidget(card_status)
        layout.addLayout(cards)

        topo = QHBoxLayout()
        secao = QLabel("Resultado do ping")
        secao.setObjectName("secao")
        self.btn_ping = QPushButton("Executar diagnóstico")
        self.btn_ping.setCursor(Qt.PointingHandCursor)
        self.btn_ping.clicked.connect(self.iniciar_diagnostico)
        topo.addWidget(secao)
        topo.addStretch()
        topo.addWidget(self.btn_ping)
        layout.addLayout(topo)

        self.saida_ping = QPlainTextEdit()
        self.saida_ping.setReadOnly(True)
        self.saida_ping.setPlaceholderText("Clique em \"Executar diagnóstico\" para testar a rede.")
        layout.addWidget(self.saida_ping)
        return aba

    def iniciar_diagnostico(self):
        self.btn_ping.setEnabled(False)
        self.btn_ping.setText("Testando...")
        self.saida_ping.setPlainText(f"Disparando ping para {ALVO_PING}...")
        self.lbl_status_rede.setText("Testando...")
        pintar(self.lbl_status_rede, COR_ALERTA)
        self.statusBar().showMessage("Rede em andamento...")
        threading.Thread(target=testar_rede, daemon=True).start()

    def ping_finalizado(self, ip_local, saida, ok):
        self.lbl_ip.setText(ip_local)
        self.saida_ping.setPlainText(saida)
        if ok:
            self.lbl_status_rede.setText("Online")
            pintar(self.lbl_status_rede, COR_OK)
        else:
            self.lbl_status_rede.setText("Sem resposta")
            pintar(self.lbl_status_rede, COR_ERRO)
        self.btn_ping.setEnabled(True)
        self.btn_ping.setText("Executar diagnóstico")
        self.statusBar().showMessage("Diagnóstico concluído.")

    def criar_aba_honeypot(self):
        aba = QWidget()
        layout = QVBoxLayout(aba)
        layout.setContentsMargins(0, 20, 0, 12)
        layout.setSpacing(16)

        cards = QHBoxLayout()
        cards.setSpacing(14)
        card_estado, self.lbl_estado_hp = criar_card("Estado", "Parado")
        card_alertas, self.lbl_total_alertas = criar_card("Alertas registrados", "0")
        cards.addWidget(card_estado)
        cards.addWidget(card_alertas)

        self.chips = {}
        for porta, nome in PORTAS_HONEYPOT.items():
            card, valor = criar_card(f"Porta {porta} ({nome})", "Inativa")
            pintar(valor, COR_SUAVE)
            self.chips[porta] = valor
            cards.addWidget(card)
        layout.addLayout(cards)

        topo = QHBoxLayout()
        secao = QLabel("Conexões detectadas")
        secao.setObjectName("secao")
        self.btn_limpar = QPushButton("Limpar registros")
        self.btn_limpar.setObjectName("secundario")
        self.btn_limpar.setCursor(Qt.PointingHandCursor)
        self.btn_limpar.clicked.connect(self.limpar_alertas)
        self.btn_honeypot = QPushButton("Armar honeypot")
        self.btn_honeypot.setCursor(Qt.PointingHandCursor)
        self.btn_honeypot.clicked.connect(self.alternar_honeypot)
        topo.addWidget(secao)
        topo.addStretch()
        topo.addWidget(self.btn_limpar)
        topo.addSpacing(8)
        topo.addWidget(self.btn_honeypot)
        layout.addLayout(topo)

        self.tabela_alertas = criar_tabela(["Horário", "Porta alvo", "IP do atacante", "Porta de origem"])
        layout.addWidget(self.tabela_alertas)

        ajuda = QLabel("Abra qualquer porta armada para gerar um alerta de conexao externa/VPN.")
        ajuda.setObjectName("ajuda")
        layout.addWidget(ajuda)
        return aba

    def alternar_honeypot(self):
        if self.ativas > 0:
            self.parar.set()
            self.btn_honeypot.setEnabled(False)
            self.btn_honeypot.setText("Encerrando...")
            self.statusBar().showMessage("Encerrando honeypot...")
            return

        self.parar = threading.Event()
        self.erros.clear()
        self.ativas = len(PORTAS_HONEYPOT)

        for porta in PORTAS_HONEYPOT:
            threading.Thread(target=armadilha, args=(porta, self.parar), daemon=True).start()

        self.btn_honeypot.setText("Parar honeypot")
        trocar_perigo(self.btn_honeypot, True)
        self.lbl_estado_hp.setText("Monitorando")
        pintar(self.lbl_estado_hp, COR_OK)
        self.statusBar().showMessage("Honeypot ativo em todas as interfaces (0.0.0.0).")

    def atualizar_porta(self, porta, estado, detalhe):
        chip = self.chips[porta]
        if estado == "armada":
            chip.setText("Armada")
            pintar(chip, COR_OK)
        elif estado == "erro":
            self.erros.add(porta)
            chip.setText("Erro")
            chip.setToolTip(detalhe)
            pintar(chip, COR_ERRO)
            self.statusBar().showMessage(f"Erro na porta {porta}: {detalhe}")
        elif estado == "parada":
            self.ativas -= 1
            if porta not in self.erros:
                chip.setText("Inativa")
                pintar(chip, COR_SUAVE)
            if self.ativas <= 0:
                self.honeypot_encerrado()

    def honeypot_encerrado(self):
        self.ativas = 0
        self.btn_honeypot.setEnabled(True)
        self.btn_honeypot.setText("Armar honeypot")
        trocar_perigo(self.btn_honeypot, False)
        self.lbl_estado_hp.setText("Parado")
        pintar(self.lbl_estado_hp, COR_TEXTO)
        if self.erros:
            self.statusBar().showMessage("Honeypot encerrado com erro. Portas abaixo de 1024 podem exigir permissão de administrador.")
        else:
            self.statusBar().showMessage("Honeypot encerrado.")

    def registrar_alerta(self, porta, ip, porta_origem):
        self.tabela_alertas.insertRow(0)
        hora = datetime.now().strftime("%H:%M:%S")
        self.tabela_alertas.setItem(0, 0, criar_item(hora))
        self.tabela_alertas.setItem(0, 1, criar_item(str(porta), COR_ALERTA, True))
        self.tabela_alertas.setItem(0, 2, criar_item(ip, COR_ERRO, True))
        self.tabela_alertas.setItem(0, 3, criar_item(str(porta_origem), None, True))
        self.total_alertas += 1
        self.lbl_total_alertas.setText(str(self.total_alertas))
        pintar(self.lbl_total_alertas, COR_ERRO)
        self.statusBar().showMessage(f"Alerta: conexão na porta {porta} vinda de {ip}:{porta_origem}")

    def limpar_alertas(self):
        self.tabela_alertas.setRowCount(0)
        self.total_alertas = 0
        self.lbl_total_alertas.setText("0")
        pintar(self.lbl_total_alertas, COR_TEXTO)

    def criar_aba_auditoria(self):
        aba = QWidget()
        layout = QVBoxLayout(aba)
        layout.setContentsMargins(0, 20, 0, 12)
        layout.setSpacing(16)

        cards = QHBoxLayout()
        cards.setSpacing(14)
        card_total, self.lbl_verificadas = criar_card("Portas verificadas", "0")
        card_abertas, self.lbl_abertas = criar_card("Abertas", "0")
        card_fechadas, self.lbl_fechadas = criar_card("Fechadas", "0")
        cards.addWidget(card_total)
        cards.addWidget(card_abertas)
        cards.addWidget(card_fechadas)
        layout.addLayout(cards)

        topo = QHBoxLayout()
        secao = QLabel("Portas em 127.0.0.1")
        secao.setObjectName("secao")
        self.btn_auditar = QPushButton("Iniciar varredura")
        self.btn_auditar.setCursor(Qt.PointingHandCursor)
        self.btn_auditar.clicked.connect(self.iniciar_auditoria)
        topo.addWidget(secao)
        topo.addStretch()
        topo.addWidget(self.btn_auditar)
        layout.addLayout(topo)

        self.tabela_portas = criar_tabela(["Porta", "Serviço", "Status"])
        layout.addWidget(self.tabela_portas)
        return aba

    def iniciar_auditoria(self):
        self.btn_auditar.setEnabled(False)
        self.btn_auditar.setText("Varrendo...")
        self.statusBar().showMessage("Auditoria de portas em andamento...")
        threading.Thread(target=auditar_portas, daemon=True).start()

    def auditoria_finalizada(self, resultados):
        self.tabela_portas.setRowCount(0)
        abertas = 0

        for porta, aberta in resultados:
            linha = self.tabela_portas.rowCount()
            self.tabela_portas.insertRow(linha)
            self.tabela_portas.setItem(linha, 0, criar_item(str(porta), None, True))
            self.tabela_portas.setItem(linha, 1, criar_item(PORTAS_AUDITORIA[porta]))
            if aberta:
                abertas += 1
                self.tabela_portas.setItem(linha, 2, criar_item("Aberta", COR_ALERTA, True))
            else:
                self.tabela_portas.setItem(linha, 2, criar_item("Fechada", COR_OK, True))

        self.lbl_verificadas.setText(str(len(resultados)))
        self.lbl_abertas.setText(str(abertas))
        self.lbl_fechadas.setText(str(len(resultados) - abertas))
        pintar(self.lbl_abertas, COR_ALERTA if abertas else COR_TEXTO)
        pintar(self.lbl_fechadas, COR_OK)

        self.btn_auditar.setEnabled(True)
        self.btn_auditar.setText("Iniciar varredura")
        self.statusBar().showMessage(f"Varredura concluída: {abertas} porta(s) aberta(s).")

    def closeEvent(self, evento):
        self.parar.set()
        evento.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(ESTILO)
    janela = Janela()
    janela.show()
    sys.exit(app.exec())