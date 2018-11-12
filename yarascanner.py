#!/user/bin/env python3
"""
YARA SCANNING TOOL
Designed for Searching for keywords in e-mails using yara rules.
This tool can be multiple purpose, and is technically capable of scanning
any file with minor changes (line 77).

Written by James Weston james@forscie.com
"""

import sys
import os
import time
import glob
import yara
import multiprocessing
from shutil import copy2
from datetime import date
import signal
import argparse

global VERSION
VERSION = "v1.0"


def scan_complete(MANAGED_VALUES):
    sys.stdout.write('\n\n--------------------------------------------------------------------------------')
    sys.stdout.write('>> YARA SCAN COMPLETE: '+time.asctime(time.localtime(time.time()))+'\n')
    sys.stdout.write(str(MANAGED_VALUES['matched'])+' of '+str(MANAGED_VALUES['total'])+' matched, ')
    sys.stdout.write(str(len(MANAGED_VALUES['skipped']))+' not scanned.\n')
    sys.stdout.write('Results saved in '+str(MANAGED_VALUES['target']+'\n'))
    if len(MANAGED_VALUES['skipped']) > 0:
        sys.stdout.write('\nNot scanned:\n')
        print(*MANAGED_VALUES['skipped'], sep='\n')
    sys.exit(0)


def copy_files(file_path, out_dir):
    name = os.path.basename(file_path)
    if not os.path.exists(os.path.join(out_dir, name)):
        copy2(file_path, os.path.join(out_dir, name))
    else:
        base, extension = os.path.splitext(name)
        i = 1
        while os.path.exists(os.path.join(out_dir, '{}_{}{}'.format(base, i, extension))):
            i += 1
        copy2(file_path, os.path.join(out_dir, '{}_{}{}'.format(base, i, extension)))


def save_skipped(MANAGED_VALUES):
    skipped_target = MANAGED_VALUES['target'] + '\\NOT SCANNED\\'
    if not os.path.exists(skipped_target):
        os.makedirs(skipped_target)
    copy_files(MANAGED_VALUES['current'], skipped_target)


def yara_match(match_dict):
    if match_dict.get('matches'):
        MANAGED_VALUES['matched'] += 1
        copy_files(MANAGED_VALUES['current'], MANAGED_VALUES['target'])


def scan_messages(MANAGED_VALUES):
    rules = yara.compile(MANAGED_VALUES['yara'])
    try:
        matches = rules.match(MANAGED_VALUES['current'], callback=yara_match, which_callbacks=yara.CALLBACK_MATCHES)
        MANAGED_VALUES['scanned'] += 1
        #time.sleep(1)  # JUST FOR TESTING!!!!
    except:
        skipped = MANAGED_VALUES['skipped']
        skipped.append(MANAGED_VALUES['current'])
        MANAGED_VALUES['skipped'] = skipped
        save_skipped(MANAGED_VALUES)


def enum_messages(dname):
    sstring = dname + "\\**\\*.msg"
    return glob.glob(sstring, recursive=True)


def running_time(elapsed):
    d = int(elapsed / (60 * 60 * 24))
    h = int(elapsed / (60 * 60))
    m = int((elapsed % (60 * 60)) / 60)
    s = int(elapsed % 60)
    return "{:>02}:{:>02}:{:>02}:{:>02}".format(d, h, m, s)


def monitor_status(MANAGED_VALUES):
    time_start = time.time()
    while MANAGED_VALUES['running']:
        perc_format = "{0:."+'1'+"f}"
        percent = perc_format.format(100 * (MANAGED_VALUES['scanned'] / float(MANAGED_VALUES['total'])))
        elapsed = time.time() - time_start
        sys.stdout.write('('+str(MANAGED_VALUES['scanned'])+'/'+str(MANAGED_VALUES['total'])+') '+'files scanned, ('+str(MANAGED_VALUES['matched'])+') matched. ')
        sys.stdout.write('| '+percent+'% | '+running_time(elapsed)+'\r')
        sys.stdout.flush()


def start_message():
    sys.stdout.write('--------------------------------------------------------------------------------')
    sys.stdout.write('>> YARA SCAN STARTED: '+time.asctime(time.localtime(time.time()))+'\n')


def welcome_message():
    print('''         __   __                ____                                  
         \ \ / /_ _ _ __ __ _  / ___|  ___ __ _ _ __  _ __   ___ _ __ 
          \ V / _` | '__/ _` | \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
           | | (_| | | | (_| |  ___) | (_| (_| | | | | | | |  __/ |   
           |_|\__,_|_|  \__,_| |____/ \___\__,_|_| |_|_| |_|\___|_| 
                                                                  ''' + VERSION )


def gen_dir(dst_dir):
    date_time = time.asctime(time.localtime(time.time()))
    date_time = date_time.replace(' ', '_').replace(':', '-')
    result_dir = dst_dir + '\\YARA_RESULTS_' + date_time + '\\'
    return result_dir


def check_inputs(yara_path, src_dir, dst_dir):
    if os.path.isfile(yara_path) and os.path.isdir(src_dir) and os.path.isdir(dst_dir):
        if yara_path.endswith('.yara'):
            return True
    else:
        print('yarascanner.py: error: the supplied paths are incorrect, please check')


def parse_args():
    global ARGS
    parser = argparse.ArgumentParser(description='USE YARA RULES TO SCAN FILES. Written by James Weston (james.weston@inmarsat.com)')
    required = parser.add_argument_group('required arguments')
    required.add_argument('-y', '--yara', help='a Yara rule file (.yara)', required=True)
    required.add_argument('-s', '--src', help='a source directory to scan', required=True)
    required.add_argument('-o', '--out', help='an output directory to store results', required=True)
    ARGS = vars(parser.parse_args())


def signal_handler(sig, frame):
    sys.stdout.write('\n--------------------------------------------------------------------------------')
    sys.stdout.write('>> YARA SCAN INTERUPTED: '+time.asctime(time.localtime(time.time()))+'\n\n')
    sys.exit(0)


def main():
    welcome_message()
    signal.signal(signal.SIGINT, signal_handler)
    parse_args()

    yara_path = ARGS['yara']
    src_dir = ARGS['src']
    dst_dir = ARGS['out']

    if check_inputs(yara_path, src_dir, dst_dir):
        result_dir = gen_dir(dst_dir)
        if not os.path.exists(result_dir):
            os.makedirs(result_dir)
        start_message()

        with multiprocessing.Manager() as manager:
            global MANAGED_VALUES
            MANAGED_VALUES = manager.dict()
            MANAGED_VALUES['yara'] = yara_path
            MANAGED_VALUES['target'] = result_dir
            MANAGED_VALUES['total'] = len(enum_messages(src_dir))
            MANAGED_VALUES['matched'] = 0
            MANAGED_VALUES['scanned'] = 0
            MANAGED_VALUES['running'] = True
            MANAGED_VALUES['skipped'] = list()

            p1 = multiprocessing.Process(target=monitor_status, args=(MANAGED_VALUES,))
            p1.start()

            for msg in enum_messages(src_dir):
                MANAGED_VALUES['current'] = msg
                scan_messages(MANAGED_VALUES)
            MANAGED_VALUES['running'] = False
            p1.join()
            scan_complete(MANAGED_VALUES)


# Main body
if __name__ == '__main__':
    main()
