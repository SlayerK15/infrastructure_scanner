# main.py
from src.scanner import AWSScanner

def main():
    scanner = AWSScanner('config/config.yaml')
    scanner.run()

if __name__ == '__main__':
    main()
