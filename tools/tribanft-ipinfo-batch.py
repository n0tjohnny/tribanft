#!/usr/bin/env python3
"""
tribanft-ipinfo-batch.py

Serviço de geolocalização em lote para o tribanft
- Executa periodicamente para geolocalizar IPs do blacklist
- Respeita limites da API do ipinfo.io
- Pode ser executado como serviço systemd
"""

import sys
import os
import argparse
import logging
import time
from pathlib import Path
from datetime import datetime

# Adiciona o diretório do projeto ao path
sys.path.insert(0, '/root/bruteforce_detector')

from bruteforce_detector.config import get_config
from bruteforce_detector.managers.ipinfo_batch_manager import IPInfoBatchManager
from bruteforce_detector.utils.logging import setup_logging


def run_batch_service(config, args):
    """Executa o serviço de geolocalização em lote"""
    logger = logging.getLogger(__name__)
    
    logger.info("="*70)
    logger.info("🚀 Iniciando Serviço de Geolocalização em Lote - TribanFT")
    logger.info("="*70)
    
    # Inicializa o gerenciador
    ipinfo_manager = IPInfoBatchManager(config, api_token=args.token)
    
    # Exibe estatísticas iniciais
    if args.show_stats:
        ipinfo_manager.print_stats()
    
    iteration = 0
    
    try:
        while True:
            iteration += 1
            logger.info(f"\n{'='*70}")
            logger.info(f"🔄 Iteração #{iteration} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            logger.info("="*70)
            
            # Processa batch de IPs
            processed = ipinfo_manager.process_blacklist_batch(
                max_requests=args.batch_size
            )
            
            # Exibe estatísticas
            stats = ipinfo_manager.get_stats_summary()
            logger.info(f"\n📊 Estatísticas:")
            logger.info(f"   IPs processados nesta iteração: {processed}")
            logger.info(f"   Requisições hoje: {stats['requests_today']}/{stats['daily_limit']}")
            logger.info(f"   Disponíveis hoje: {stats['remaining_today']}")
            logger.info(f"   Cache size: {stats['cache_size']} IPs")
            
            # Se não há mais IPs para processar ou limite diário atingido
            if processed == 0:
                logger.info("✅ Nenhum IP novo para processar ou limite atingido")
                
                if not args.daemon:
                    logger.info("🏁 Modo único: encerrando serviço")
                    break
            
            # Em modo daemon, aguarda antes da próxima iteração
            if args.daemon:
                if stats['remaining_today'] == 0:
                    # Se limite diário atingido, aguarda até meia-noite
                    logger.info(f"⏰ Limite diário atingido. Aguardando reset em meia-noite...")
                    time.sleep(3600)  # Aguarda 1 hora e verifica novamente
                else:
                    # Aguarda intervalo configurado
                    logger.info(f"⏸️  Aguardando {args.interval} segundos até próxima iteração...")
                    time.sleep(args.interval)
            else:
                # Modo único: encerra após processar
                logger.info("🏁 Modo único: encerrando serviço")
                break
                
    except KeyboardInterrupt:
        logger.info("\n⏹️  Serviço interrompido pelo usuário")
    except Exception as e:
        logger.error(f"❌ Erro no serviço: {e}", exc_info=True)
        sys.exit(1)
    finally:
        logger.info("\n" + "="*70)
        logger.info("📊 ESTATÍSTICAS FINAIS")
        logger.info("="*70)
        ipinfo_manager.print_stats()
        logger.info("🏁 Serviço de Geolocalização em Lote finalizado")


def main():
    parser = argparse.ArgumentParser(
        description='Serviço de Geolocalização em Lote para TribanFT',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
📝 EXEMPLOS DE USO:
  %(prog)s                                    # Executa uma vez
  %(prog)s --daemon                           # Executa continuamente
  %(prog)s --daemon --interval 3600           # Executa a cada 1 hora
  %(prog)s --batch-size 200                   # Processa 200 IPs por vez
  %(prog)s --show-stats                       # Exibe estatísticas
  %(prog)s --token YOUR_TOKEN                 # Usa token customizado

🔧 CONFIGURAÇÃO DO TOKEN:
  Salve seu token em: /etc/tribanft/ipinfo_token.txt
  
📦 INSTALAÇÃO COMO SERVIÇO:
  sudo systemctl enable tribanft-ipinfo-batch.service
  sudo systemctl start tribanft-ipinfo-batch.service
  sudo systemctl status tribanft-ipinfo-batch.service
        """
    )
    
    parser.add_argument(
        '--daemon', '-d',
        action='store_true',
        help='Executa como daemon (modo contínuo)'
    )
    
    parser.add_argument(
        '--interval', '-i',
        type=int,
        default=3600,
        help='Intervalo entre iterações em segundos (padrão: 3600 = 1 hora)'
    )
    
    parser.add_argument(
        '--batch-size', '-b',
        type=int,
        default=100,
        help='Número máximo de IPs a processar por iteração (padrão: 100)'
    )
    
    parser.add_argument(
        '--token', '-t',
        type=str,
        help='Token da API do ipinfo.io (ou salve em /etc/tribanft/ipinfo_token.txt)'
    )
    
    parser.add_argument(
        '--show-stats', '-s',
        action='store_true',
        help='Exibe estatísticas antes de iniciar'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Modo verboso (debug)'
    )
    
    args = parser.parse_args()
    
    # Valida intervalo
    if args.interval < 60:
        print("❌ Intervalo mínimo: 60 segundos")
        sys.exit(1)
    
    if args.batch_size < 1 or args.batch_size > 1000:
        print("❌ Batch size deve estar entre 1 e 1000")
        sys.exit(1)
    
    # Configura logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(level=log_level)
    
    # Obtém configuração
    config = get_config()
    
    # Cria diretório de configuração se não existir
    config_dir = Path("/etc/tribanft")
    config_dir.mkdir(parents=True, exist_ok=True)
    
    # Executa serviço
    run_batch_service(config, args)


if __name__ == "__main__":
    main()
