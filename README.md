# YaraScanner

         __   __                ____
         \ \ / /_ _ _ __ __ _  / ___|  ___ __ _ _ __  _ __   ___ _ __
          \ V / _` | '__/ _` | \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
           | | (_| | | | (_| |  ___) | (_| (_| | | | | | | |  __/ |
           |_|\__,_|_|  \__,_| |____/ \___\__,_|_| |_|_| |_|\___|_|
                                                                  v1.0
usage: yarascanner.py [-h] -y YARA -s SRC -o OUT

USE YARA RULES TO SCAN FILES. Written by James Weston (james@forscie.com)

optional arguments:
  -h, --help            show this help message and exit

required arguments:
  -y YARA, --yara YARA  a Yara rule file (.yara)
  -s SRC, --src SRC     a source directory to scan
  -o OUT, --out OUT     an output directory to store results
