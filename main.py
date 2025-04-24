#!/usr/bin/env python3

import sys
import argparse
from modules.info_gathering import InfoGatherer
from modules.vuln_scanner import VulnerabilityScanner
from modules.exploiter import Exploiter
from modules.report_generator import ReportGenerator
from utils.banner import display_banner
from utils.logger import setup_logger

def parse_arguments():
    parser = argparse.ArgumentParser(description='CyberSentinel - Penetration Testing Framework')
    parser.add_argument('-t', '--target', help='Target URL or IP address', required=True)
    parser.add_argument('-m', '--mode', choices=['recon', 'scan', 'exploit', 'all'], default='all',
                        help='Operation mode: recon, scan, exploit, or all')
    parser.add_argument('-o', '--output', help='Output report file name', default='pentest_report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    return parser.parse_args()

def main():
    args = parse_arguments()
    logger = setup_logger(args.verbose)
    
    display_banner()
    logger.info(f"Starting penetration test against {args.target}")
    
    try:
        # Initialize modules
        info_gatherer = InfoGatherer(args.target, logger)
        vuln_scanner = VulnerabilityScanner(args.target, logger)
        exploiter = Exploiter(args.target, logger)
        report_gen = ReportGenerator(args.output, logger)
        
        results = {}
        
        # Information Gathering
        if args.mode in ['recon', 'all']:
            logger.info("Starting information gathering phase...")
            results['recon'] = info_gatherer.gather_info()
        
        # Vulnerability Scanning
        if args.mode in ['scan', 'all']:
            logger.info("Starting vulnerability scanning phase...")
            results['vulnerabilities'] = vuln_scanner.scan()
        
        # Exploitation
        if args.mode in ['exploit', 'all']:
            logger.info("Starting exploitation phase...")
            results['exploits'] = exploiter.run_exploits()
        
        # Generate Report
        logger.info("Generating final report...")
        report_gen.generate(results)
        
        logger.info(f"Penetration test completed. Report saved as {args.output}")
        
    except KeyboardInterrupt:
        logger.error("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
