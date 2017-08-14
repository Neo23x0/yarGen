#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Imphash Lookup in yarGens database
#
# Florian Roth

import os
import gzip
import pickle
import traceback
import argparse
import sys
import re
import signal as signal_module
import readline
from colorama import init, Fore, Back, Style
from collections import Counter

readline.parse_and_bind('tab: complete')
readline.parse_and_bind('set editing-mode vi')

__AUTHOR__ = "Florian Roth"
__VERSION__ = "0.1"

VALID_LOOKUPS = ["strings", "exports", "opcodes", "imphash"]

def get_abs_path(filename):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)

def load(filename):
    file = gzip.GzipFile(filename, 'rb')
    buffer = ""
    while 1:
        data = file.read()
        if data == "":
            break
        buffer += data
    object = pickle.loads(buffer)
    del (buffer)
    file.close()
    return object

def init_database(lookups):
    """
    Initialize the database for the lookups
    :return:
    """

    opcodes_num = 0
    strings_num = 0
    imphash_num = 0
    exports_num = 0

    # Initialize all databases
    for file in os.listdir(get_abs_path("./dbs/")):
        if not file.endswith(".db"):
            continue
        filePath = os.path.join("./dbs/", file)

        # String databases
        if file.startswith("good-strings") and "strings" in lookups:
            try:
                print "[+] Loading %s ..." % filePath
                good_pickle = load(get_abs_path(filePath))
                good_strings_db.update(good_pickle)
                print "[+] Total: %s / Added %d entries" % (
                len(good_strings_db), len(good_strings_db) - strings_num)
                strings_num = len(good_strings_db)
            except Exception, e:
                traceback.print_exc()
        # Opcode databases
        if file.startswith("good-opcodes") and "opcodes" in lookups:
            try:
                if use_opcodes:
                    print "[+] Loading %s ..." % filePath
                    good_op_pickle = load(get_abs_path(filePath))
                    good_opcodes_db.update(good_op_pickle)
                    print "[+] Total: %s (removed duplicates) / Added %d entries" % (
                    len(good_opcodes_db), len(good_opcodes_db) - opcodes_num)
                    opcodes_num = len(good_opcodes_db)
            except Exception, e:
                use_opcodes = False
                traceback.print_exc()
        # Imphash databases
        if file.startswith("good-imphash") and "imphash" in lookups:
            try:
                print "[+] Loading %s ..." % filePath
                good_imphashes_pickle = load(get_abs_path(filePath))
                good_imphashes_db.update(good_imphashes_pickle)
                print "[+] Total: %s / Added %d entries" % (
                len(good_imphashes_db), len(good_imphashes_db) - imphash_num)
                imphash_num = len(good_imphashes_db)
            except Exception, e:
                traceback.print_exc()
        # Export databases
        if file.startswith("good-exports") and "exports" in lookups:
            try:
                print "[+] Loading %s ..." % filePath
                good_exports_pickle = load(get_abs_path(filePath))
                good_exports_db.update(good_exports_pickle)
                print "[+] Total: %s / Added %d entries" % (
                len(good_exports_db), len(good_exports_db) - exports_num)
                exports_num = len(good_exports_db)
            except Exception, e:
                traceback.print_exc()

def print_welcome():
    print Style.RESET_ALL
    print Fore.WHITE + Back.BLUE
    print " ".ljust(80)
    print "                      ______              __                __             ".ljust(80)
    print "    __  ______ ______/ ____/__  ____     / /   ____  ____  / /____  ______ ".ljust(80)
    print "   / / / / __ `/ ___/ / __/ _ \\/ __ \\   / /   / __ \\/ __ \\/ //_/ / / / __ \\".ljust(80)
    print "  / /_/ / /_/ / /  / /_/ /  __/ / / /  / /___/ /_/ / /_/ / ,< / /_/ / /_/ /".ljust(80)
    print "  \\__, /\\__,_/_/   \\____/\\___/_/ /_/  /_____/\\____/\\____/_/|_|\\__,_/ .___/ ".ljust(80)
    print " /____/                                                           /_/      ".ljust(80)
    print " ".ljust(80)
    print ("  " + __AUTHOR__ + " - " + __VERSION__ + "").ljust(80)
    print " ".ljust(80) + Style.RESET_ALL
    print Style.RESET_ALL + " "


# CTRL+C Handler --------------------------------------------------------------
def signal_handler(signal_name, frame):
    print "------------------------------------------------------------------------------\n"
    print 'INTERRUPTED'
    sys.exit(0)


# MAIN ################################################################
if __name__ == '__main__':
    # Parse Arguments
    parser = argparse.ArgumentParser(description='yarGen')

    parser.add_argument('-f', help='File that contains imphashes/strings/exports')
    parser.add_argument('-l', action='append', nargs='+', help='Activate the following lookups only (seperated by '
                                                               'space; valid values are: strings, opcodes, imphash, '
                                                               'exports)', metavar='activelookups')

    args = parser.parse_args()

    # Print Welcome
    print_welcome()

    # Signal handler for CTRL+C ---------------------------------------
    signal_module.signal(signal_module.SIGINT, signal_handler)

    # Error checks
    if not args.l:
        print "[E] You must define at least on lookup module -l [%s]" % " ".join(VALID_LOOKUPS)
        sys.exit(1)
    for l in args.l[0]:
        if l not in VALID_LOOKUPS:
            print "[E] '%s' is an unknown lookup - valid lookups are: %s" % (l, ", ".join(VALID_LOOKUPS))
            sys.exit(1)

    # Active lookups
    active_lookpups = args.l[0]

    # Initialize the lookup databases
    good_strings_db = Counter()
    good_opcodes_db = Counter()
    good_imphashes_db = Counter()
    good_exports_db = Counter()

    init_database(active_lookpups)

    # File input or command line input
    if args.f:
        print "not yet implemented"
    else:
        # Input loop
        print "Provide a value (%s) as input" % ", ".join(active_lookpups)
        while True:
            input_value = raw_input("> ")

            types = []

            # Determine input values format
            # MD5 > Imphash
            res_md5 = re.search(r'^[\s]*([A-Fa-f0-9]{32})[\s]*$', input_value)
            if res_md5:
                types.append("imphash")
                # Cleanup value
                input_value = res_md5.group(0)
                # Could also be opcode or string
                types.append("opcode")
                types.append("string")
            # Opcode
            res_op = re.search(r'^[\s]*([A-Fa-f0-9\s]+)[\s]*$', input_value)
            if res_op:
                types.append("opcode")
                # Cleanup value
                input_value = res_op.group(0)
                input_value = re.sub(r' ', '', input_value, count=0)
                # Could also be a string
                types.append("string")
            # String
            if not res_md5 and not res_op:
                types.append("string")

            # Type lookups
            if "imphash" in types:
                if "imphash" in active_lookpups:
                    if input_value in good_imphashes_db:
                        print Fore.BLACK, Back.GREEN, "IMPHASH KNOWN GOOD FROM %d FILES" \
                                                      % good_imphashes_db[input_value], Style.RESET_ALL
                    else:
                        print Fore.BLACK, Back.WHITE, "IMPHASH UNKNOWN", Style.RESET_ALL
            if "string" in types:
                if "strings" in active_lookpups:
                    if input_value in good_strings_db:
                        print Fore.BLACK, Back.GREEN, "STRING KNOWN GOOD IN %d FILES" \
                                                      % good_strings_db[input_value], Style.RESET_ALL
                    else:
                        print Fore.BLACK, Back.WHITE, "STRING UNKNOWN", Style.RESET_ALL
                if "exports" in active_lookpups:
                    if input_value in good_exports_db:
                        print Fore.BLACK, Back.GREEN, "EXPORT KNOWN GOOD IN %d FILES" \
                                                      % good_exports_db[input_value], Style.RESET_ALL
                    else:
                        print Fore.BLACK, Back.WHITE, "EXPORT UNKNOWN", Style.RESET_ALL