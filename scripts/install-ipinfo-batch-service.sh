#!/bin/bash
#
# install-ipinfo-batch-service.sh
# Script de instalação do serviço de geolocalização em lote do TribanFT
#

set -e  # Exit on error

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}TribanFT - Instalação do Serviço de Geolocalização em Lote${NC}"
echo -e "${BLUE}========================================${NC}\n"

# Verifica se está rodando como root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}❌ Este script deve ser executado como root${NC}"
    echo -e "${YELLOW}💡 Use: sudo $0${NC}"
    exit 1
fi

# Variáveis
PROJECT_DIR="/root/bruteforce_detector"
SERVICE_FILE="systemd/tribanft-ipinfo-batch.service"
SCRIPT_FILE="tools/tribanft-ipinfo-batch.py"
CONFIG_DIR="/etc/tribanft"
TOKEN_FILE="${CONFIG_DIR}/ipinfo_token.txt"
CACHE_DIR="/var/lib/tribanft/ipinfo_cache"

# Verifica se o diretório do projeto existe
if [ ! -d "$PROJECT_DIR" ]; then
    echo -e "${RED}❌ Diretório do projeto não encontrado: ${PROJECT_DIR}${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Diretório do projeto encontrado${NC}"

# Cria diretórios necessários
echo -e "\n${BLUE}📁 Criando diretórios...${NC}"
mkdir -p "$CONFIG_DIR"
mkdir -p "$CACHE_DIR"
echo -e "${GREEN}✅ Diretórios criados${NC}"

# Copia arquivos
echo -e "\n${BLUE}📋 Copiando arquivos...${NC}"

# Copia script principal
if [ -f "$PROJECT_DIR/$SCRIPT_FILE" ]; then
    chmod +x "$PROJECT_DIR/$SCRIPT_FILE"
    echo -e "${GREEN}✅ Script principal configurado${NC}"
else
    echo -e "${RED}❌ Script não encontrado: ${PROJECT_DIR}/${SCRIPT_FILE}${NC}"
    exit 1
fi

# Copia arquivo de serviço
if [ -f "$PROJECT_DIR/$SERVICE_FILE" ]; then
    cp "$PROJECT_DIR/$SERVICE_FILE" /etc/systemd/system/
    echo -e "${GREEN}✅ Arquivo de serviço copiado${NC}"
else
    echo -e "${RED}❌ Arquivo de serviço não encontrado: ${PROJECT_DIR}/${SERVICE_FILE}${NC}"
    exit 1
fi

# Configura token (se ainda não existir)
echo -e "\n${BLUE}🔑 Configuração do Token do IPInfo.io${NC}"
if [ -f "$TOKEN_FILE" ]; then
    echo -e "${YELLOW}⚠️  Token já configurado em: ${TOKEN_FILE}${NC}"
    read -p "Deseja atualizar o token? (s/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Ss]$ ]]; then
        read -p "Digite seu token do ipinfo.io: " TOKEN
        echo "$TOKEN" > "$TOKEN_FILE"
        chmod 600 "$TOKEN_FILE"
        echo -e "${GREEN}✅ Token atualizado${NC}"
    fi
else
    echo -e "${YELLOW}💡 Você pode obter um token gratuito em: https://ipinfo.io/signup${NC}"
    read -p "Digite seu token do ipinfo.io (ou pressione Enter para usar sem token): " TOKEN
    if [ -n "$TOKEN" ]; then
        echo "$TOKEN" > "$TOKEN_FILE"
        chmod 600 "$TOKEN_FILE"
        echo -e "${GREEN}✅ Token configurado${NC}"
    else
        echo -e "${YELLOW}⚠️  Usando serviço sem token (limite: 50k requisições/mês)${NC}"
    fi
fi

# Recarrega systemd
echo -e "\n${BLUE}🔄 Recarregando systemd...${NC}"
systemctl daemon-reload
echo -e "${GREEN}✅ Systemd recarregado${NC}"

# Pergunta se deseja habilitar e iniciar o serviço
echo -e "\n${BLUE}🚀 Configuração do Serviço${NC}"
read -p "Deseja habilitar o serviço para iniciar automaticamente? (S/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    systemctl enable tribanft-ipinfo-batch.service
    echo -e "${GREEN}✅ Serviço habilitado para iniciar automaticamente${NC}"
fi

read -p "Deseja iniciar o serviço agora? (S/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    systemctl start tribanft-ipinfo-batch.service
    echo -e "${GREEN}✅ Serviço iniciado${NC}"
    
    # Aguarda um momento e verifica status
    sleep 2
    echo -e "\n${BLUE}📊 Status do Serviço:${NC}"
    systemctl status tribanft-ipinfo-batch.service --no-pager -l
fi

# Exibe comandos úteis
echo -e "\n${BLUE}========================================${NC}"
echo -e "${BLUE}✅ INSTALAÇÃO CONCLUÍDA!${NC}"
echo -e "${BLUE}========================================${NC}\n"

echo -e "${YELLOW}📝 Comandos úteis:${NC}"
echo -e "   ${GREEN}systemctl status tribanft-ipinfo-batch${NC}     - Verificar status"
echo -e "   ${GREEN}systemctl start tribanft-ipinfo-batch${NC}      - Iniciar serviço"
echo -e "   ${GREEN}systemctl stop tribanft-ipinfo-batch${NC}       - Parar serviço"
echo -e "   ${GREEN}systemctl restart tribanft-ipinfo-batch${NC}    - Reiniciar serviço"
echo -e "   ${GREEN}journalctl -u tribanft-ipinfo-batch -f${NC}     - Ver logs em tempo real"
echo -e "   ${GREEN}journalctl -u tribanft-ipinfo-batch -n 100${NC} - Ver últimas 100 linhas de log"

echo -e "\n${YELLOW}🔧 Configuração:${NC}"
echo -e "   Token: ${CONFIG_DIR}/ipinfo_token.txt"
echo -e "   Cache: ${CACHE_DIR}/"
echo -e "   Logs:  journalctl -u tribanft-ipinfo-batch"

echo -e "\n${YELLOW}📖 Documentação:${NC}"
echo -e "   https://github.com/n0tjohnny/tribanft\n"

exit 0
