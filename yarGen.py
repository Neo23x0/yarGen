#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# yarGen
# A Rule Generator for YARA Rules
#
# Florian Roth

__version__ = "0.22.0"

import os
import sys

if sys.version_info[0] > 2:
    raise Exception("Some modules require Python 2, so please use that version instead of Python 3")

import argparse
import re
import traceback
import operator
import datetime
import time
import scandir
import pefile
import cPickle as pickle
import gzip
import urllib
from collections import Counter
from hashlib import sha256
import signal as signal_module

try:
    from lxml import etree

    lxml_available = True
except Exception as e:
    print("[E] lxml not found - disabling PeStudio string check functionality")
    lxml_available = False

RELEVANT_EXTENSIONS = [".asp", ".vbs", ".ps", ".ps1", ".tmp", ".bas", ".bat", ".cmd", ".com", ".cpl",
                       ".crt", ".dll", ".exe", ".msc", ".scr", ".sys", ".vb", ".vbe", ".vbs", ".wsc",
                       ".wsf", ".wsh", ".input", ".war", ".jsp", ".php", ".asp", ".aspx", ".psd1", ".psm1", ".py"]

REPO_URLS = {
    'good-opcodes-part1.db': 'https://www.bsk-consulting.de/yargen/good-opcodes-part1.db',
    'good-opcodes-part2.db': 'https://www.bsk-consulting.de/yargen/good-opcodes-part2.db',
    'good-opcodes-part3.db': 'https://www.bsk-consulting.de/yargen/good-opcodes-part3.db',
    'good-opcodes-part4.db': 'https://www.bsk-consulting.de/yargen/good-opcodes-part4.db',
    'good-opcodes-part5.db': 'https://www.bsk-consulting.de/yargen/good-opcodes-part5.db',
    'good-opcodes-part6.db': 'https://www.bsk-consulting.de/yargen/good-opcodes-part6.db',
    'good-opcodes-part7.db': 'https://www.bsk-consulting.de/yargen/good-opcodes-part7.db',
    'good-opcodes-part8.db': 'https://www.bsk-consulting.de/yargen/good-opcodes-part8.db',
    'good-opcodes-part9.db': 'https://www.bsk-consulting.de/yargen/good-opcodes-part9.db',

    'good-strings-part1.db': 'https://www.bsk-consulting.de/yargen/good-strings-part1.db',
    'good-strings-part2.db': 'https://www.bsk-consulting.de/yargen/good-strings-part2.db',
    'good-strings-part3.db': 'https://www.bsk-consulting.de/yargen/good-strings-part3.db',
    'good-strings-part4.db': 'https://www.bsk-consulting.de/yargen/good-strings-part4.db',
    'good-strings-part5.db': 'https://www.bsk-consulting.de/yargen/good-strings-part5.db',
    'good-strings-part6.db': 'https://www.bsk-consulting.de/yargen/good-strings-part6.db',
    'good-strings-part7.db': 'https://www.bsk-consulting.de/yargen/good-strings-part7.db',
    'good-strings-part8.db': 'https://www.bsk-consulting.de/yargen/good-strings-part8.db',
    'good-strings-part9.db': 'https://www.bsk-consulting.de/yargen/good-strings-part9.db',

    'good-exports-part1.db': 'https://www.bsk-consulting.de/yargen/good-exports-part1.db',
    'good-exports-part2.db': 'https://www.bsk-consulting.de/yargen/good-exports-part2.db',
    'good-exports-part3.db': 'https://www.bsk-consulting.de/yargen/good-exports-part3.db',
    'good-exports-part4.db': 'https://www.bsk-consulting.de/yargen/good-exports-part4.db',
    'good-exports-part5.db': 'https://www.bsk-consulting.de/yargen/good-exports-part5.db',
    'good-exports-part6.db': 'https://www.bsk-consulting.de/yargen/good-exports-part6.db',
    'good-exports-part7.db': 'https://www.bsk-consulting.de/yargen/good-exports-part7.db',
    'good-exports-part8.db': 'https://www.bsk-consulting.de/yargen/good-exports-part8.db',
    'good-exports-part9.db': 'https://www.bsk-consulting.de/yargen/good-exports-part9.db',

    'good-imphashes-part1.db': 'https://www.bsk-consulting.de/yargen/good-imphashes-part1.db',
    'good-imphashes-part2.db': 'https://www.bsk-consulting.de/yargen/good-imphashes-part2.db',
    'good-imphashes-part3.db': 'https://www.bsk-consulting.de/yargen/good-imphashes-part3.db',
    'good-imphashes-part4.db': 'https://www.bsk-consulting.de/yargen/good-imphashes-part4.db',
    'good-imphashes-part5.db': 'https://www.bsk-consulting.de/yargen/good-imphashes-part5.db',
    'good-imphashes-part6.db': 'https://www.bsk-consulting.de/yargen/good-imphashes-part6.db',
    'good-imphashes-part7.db': 'https://www.bsk-consulting.de/yargen/good-imphashes-part7.db',
    'good-imphashes-part8.db': 'https://www.bsk-consulting.de/yargen/good-imphashes-part8.db',
    'good-imphashes-part9.db': 'https://www.bsk-consulting.de/yargen/good-imphashes-part9.db',
}

PE_STRINGS_FILE = "./3rdparty/strings.xml"

KNOWN_IMPHASHES = {'a04dd9f5ee88d7774203e0a0cfa1b941': 'PsExec',
                   '2b8c9d9ab6fefc247adaf927e83dcea6': 'RAR SFX variant'}


def get_abs_path(filename):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)


def get_files(dir, notRecursive):
    # Not Recursive
    if notRecursive:
        for filename in os.listdir(dir):
            filePath = os.path.join(dir, filename)
            if os.path.isdir(filePath):
                continue
            yield filePath
    # Recursive
    else:
        for root, directories, files in scandir.walk(dir, followlinks=False):
            for filename in files:
                filePath = os.path.join(root, filename)
                yield filePath


def parse_sample_dir(dir, notRecursive=False, generateInfo=False, onlyRelevantExtensions=False):
    # Prepare dictionary
    string_stats = {}
    opcode_stats = {}
    file_info = {}
    known_sha1sums = []

    for filePath in get_files(dir, notRecursive):
        try:
            print("[+] Processing %s ..." % filePath)

            # Get Extension
            extension = os.path.splitext(filePath)[1].lower()
            if not extension in RELEVANT_EXTENSIONS and onlyRelevantExtensions:
                if args.debug:
                    print("[-] EXTENSION %s - Skipping file %s" % (extension, filePath))
                continue

            # Info file check
            if os.path.basename(filePath) == os.path.basename(args.b) or \
                    os.path.basename(filePath) == os.path.basename(args.r):
                continue

            # Size Check
            size = 0
            try:
                size = os.stat(filePath).st_size
                if size > (args.fs * 1024 * 1024):
                    if args.debug:
                        print("[-] File is to big - Skipping file %s (use -fs to adjust this behaviour)" % (filePath))
                    continue
            except Exception as e:
                pass

            # Check and read file
            try:
                with open(filePath, 'rb') as f:
                    fileData = f.read()
            except Exception as e:
                print("[-] Cannot read file - skipping %s" % filePath)

            # Extract strings from file
            strings = extract_strings(fileData)

            # Extract opcodes from file
            opcodes = []
            if use_opcodes:
                print("[-] Extracting OpCodes: %s" % filePath)
                opcodes = extract_opcodes(fileData)

            # Add sha256 value
            if generateInfo:
                sha256sum = sha256(fileData).hexdigest()
                file_info[filePath] = {}
                file_info[filePath]["hash"] = sha256sum
                file_info[filePath]["imphash"], file_info[filePath]["exports"] = get_pe_info(fileData)

            # Skip if hash already known - avoid duplicate files
            if sha256sum in known_sha1sums:
                # if args.debug:
                print("[-] Skipping strings/opcodes from %s due to MD5 duplicate detection" % filePath)
                continue
            else:
                known_sha1sums.append(sha256sum)

            # Magic evaluation
            if not args.nomagic:
                file_info[filePath]["magic"] = fileData[:2]
            else:
                file_info[filePath]["magic"] = ""

            # File Size
            file_info[filePath]["size"] = os.stat(filePath).st_size

            # Add stats for basename (needed for inverse rule generation)
            fileName = os.path.basename(filePath)
            folderName = os.path.basename(os.path.dirname(filePath))
            if fileName not in file_info:
                file_info[fileName] = {}
                file_info[fileName]["count"] = 0
                file_info[fileName]["hashes"] = []
                file_info[fileName]["folder_names"] = []
            file_info[fileName]["count"] += 1
            file_info[fileName]["hashes"].append(sha256sum)
            if folderName not in file_info[fileName]["folder_names"]:
                file_info[fileName]["folder_names"].append(folderName)

            # Add strings to statistics
            for string in strings:
                # String is not already known
                if string not in string_stats:
                    string_stats[string] = {}
                    string_stats[string]["count"] = 0
                    string_stats[string]["files"] = []
                    string_stats[string]["files_basename"] = {}
                # String count
                string_stats[string]["count"] += 1
                # Add file information
                if fileName not in string_stats[string]["files_basename"]:
                    string_stats[string]["files_basename"][fileName] = 0
                string_stats[string]["files_basename"][fileName] += 1
                string_stats[string]["files"].append(filePath)

            # Add opcods to statistics
            for opcode in opcodes:
                # String is not already known
                if opcode not in opcode_stats:
                    opcode_stats[opcode] = {}
                    opcode_stats[opcode]["count"] = 0
                    opcode_stats[opcode]["files"] = []
                    opcode_stats[opcode]["files_basename"] = {}
                # opcode count
                opcode_stats[opcode]["count"] += 1
                # Add file information
                if fileName not in opcode_stats[opcode]["files_basename"]:
                    opcode_stats[opcode]["files_basename"][fileName] = 0
                opcode_stats[opcode]["files_basename"][fileName] += 1
                opcode_stats[opcode]["files"].append(filePath)

            if args.debug:
                print("[+] Processed " + filePath + " Size: " + str(size) + " Strings: " + str(len(string_stats)) + \
                      " OpCodes: " + str(len(opcode_stats)) + " ... ")

        except Exception as e:
            traceback.print_exc()
            print("[E] ERROR reading file: %s" % filePath)

    return string_stats, opcode_stats, file_info


def parse_good_dir(dir, notRecursive=False, onlyRelevantExtensions=True):
    # Prepare dictionary
    all_strings = Counter()
    all_opcodes = Counter()
    all_imphashes = Counter()
    all_exports = Counter()

    for filePath in get_files(dir, notRecursive):
        # Get Extension
        extension = os.path.splitext(filePath)[1].lower()
        if extension not in RELEVANT_EXTENSIONS and onlyRelevantExtensions:
            if args.debug:
                print("[-] EXTENSION %s - Skipping file %s" % (extension, filePath))
            continue

        # Size Check
        size = 0
        try:
            size = os.stat(filePath).st_size
            if size > (args.fs * 1024 * 1024):
                continue
        except Exception as e:
            pass

        # Check and read file
        try:
            with open(filePath, 'rb') as f:
                fileData = f.read()
        except Exception as e:
            print("[-] Cannot read file - skipping %s" % filePath)

        # Extract strings from file
        strings = extract_strings(fileData)
        # Append to all strings
        all_strings.update(strings)

        # Extract Opcodes from file
        opcodes = []
        if use_opcodes:
            print("[-] Extracting OpCodes: %s" % filePath)
            opcodes = extract_opcodes(fileData)
            # Append to all opcodes
            all_opcodes.update(opcodes)

        # Imphash and Exports
        (imphash, exports) = get_pe_info(fileData)
        all_exports.update(exports)
        all_imphashes.update([imphash])

        if args.debug:
            print("[+] Processed %s - %d strings %d opcodes %d exports and imphash %s" % (filePath, len(strings),
                                                                                          len(opcodes), len(exports),
                                                                                          imphash))

    # return it as a set (unique strings)
    return all_strings, all_opcodes, all_imphashes, all_exports


def extract_strings(fileData):
    # String list
    cleaned_strings = []
    # Read file data
    try:
        # Read strings
        strings_full = re.findall("[\x1f-\x7e]{6,}", fileData)
        strings_limited = re.findall("[\x1f-\x7e]{6,%d}" % args.s, fileData)
        strings_hex = extract_hex_strings(fileData)
        strings = list(set(strings_full) | set(strings_limited) | set(strings_hex))
        strings += [str("UTF16LE:%s" % ws.decode("utf-16le")) for ws in re.findall("(?:[\x1f-\x7e][\x00]){6,}", fileData)]

        # Escape strings
        for string in strings:
            # Check if last bytes have been string and not yet saved to list
            if len(string) > 0:
                string = string.replace('\\', '\\\\')
                string = string.replace('"', '\\"')
                if string not in cleaned_strings:
                    cleaned_strings.append(string.lstrip(" "))

    except Exception as e:
        if args.debug:
            traceback.print_exc()
        pass

    return cleaned_strings


def extract_opcodes(fileData):
    # String list
    opcodes = []

    # Read file data
    try:
        pe = pefile.PE(data=fileData)
        name = ""
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        pos = 0
        for sec in pe.sections:
            if (ep >= sec.VirtualAddress) and \
                    (ep < (sec.VirtualAddress + sec.Misc_VirtualSize)):
                name = sec.Name.replace('\x00', '')
                break
            else:
                pos += 1

        for section in pe.sections:
            if section.Name.rstrip("\x00") == name:
                text = section.get_data()
                # Split text into subs
                text_parts = re.split("[\x00]{3,}", text)
                # Now truncate and encode opcodes
                for text_part in text_parts:
                    if text_part == '' or len(text_part) < 8:
                        continue
                    opcodes.append(text_part[:16].encode('hex'))

    except Exception as e:
        #if args.debug:
        #    traceback.print_exc()
        pass

    return opcodes


def get_pe_info(fileData):
    """
    Get different PE attributes and hashes
    :param fileData:
    :return:
    """
    imphash = ""
    exports = []
    # Check for MZ header (speed improvement)
    if fileData[:2] != "MZ":
        return imphash, exports
    try:
        if args.debug:
            print("Extracting PE information")
        p = pefile.PE(data=fileData)
        # Imphash
        imphash = p.get_imphash()
        # Exports (names)
        for exp in p.DIRECTORY_ENTRY_EXPORT.symbols:
            exports.append(exp.name)
    except Exception as e:
        #if args.debug:
        #    traceback.print_exc()
        pass
    return imphash, exports


def sample_string_evaluation(string_stats, opcode_stats, file_info):
    # Generate Stats -----------------------------------------------------------
    print("[+] Generating statistical data ...")
    file_strings = {}
    file_opcodes = {}
    combinations = {}
    inverse_stats = {}
    max_combi_count = 0
    super_rules = []

    # OPCODE EVALUATION --------------------------------------------------------
    for opcode in opcode_stats:
        # If string occurs not too often in sample files
        if opcode_stats[opcode]["count"] < 10:
            # If string list in file dictionary not yet exists
            for filePath in opcode_stats[opcode]["files"]:
                if filePath in file_opcodes:
                    # Append string
                    file_opcodes[filePath].append(opcode)
                else:
                    # Create list and than add the first string to the file
                    file_opcodes[filePath] = []
                    file_opcodes[filePath].append(opcode)

    # STRING EVALUATION -------------------------------------------------------

    # Iterate through strings found in malware files
    for string in string_stats:

        # If string occurs not too often in (goodware) sample files
        if string_stats[string]["count"] < 10:
            # If string list in file dictionary not yet exists
            for filePath in string_stats[string]["files"]:
                if filePath in file_strings:
                    # Append string
                    file_strings[filePath].append(string)
                else:
                    # Create list and than add the first string to the file
                    file_strings[filePath] = []
                    file_strings[filePath].append(string)

                # INVERSE RULE GENERATION -------------------------------------
                if args.inverse:
                    for fileName in string_stats[string]["files_basename"]:
                        string_occurrance_count = string_stats[string]["files_basename"][fileName]
                        total_count_basename = file_info[fileName]["count"]
                        # print "string_occurance_count %s - total_count_basename %s" % ( string_occurance_count,
                        # total_count_basename )
                        if string_occurrance_count == total_count_basename:
                            if fileName not in inverse_stats:
                                inverse_stats[fileName] = []
                            if args.trace:
                                print("Appending %s to %s" % (string, fileName))
                            inverse_stats[fileName].append(string)

        # SUPER RULE GENERATION -----------------------------------------------

        if not nosuper and not args.inverse:

            # SUPER RULES GENERATOR	- preliminary work
            # If a string occurs more than once in different files
            # print sample_string_stats[string]["count"]
            if string_stats[string]["count"] > 1:
                if args.debug:
                    print("OVERLAP Count: %s\nString: \"%s\"%s" % (string_stats[string]["count"], string,
                                                                   "\nFILE: ".join(string_stats[string]["files"])))
                # Create a combination string from the file set that matches to that string
                combi = ":".join(sorted(string_stats[string]["files"]))
                # print "STRING: " + string
                if args.debug:
                    print("COMBI: " + combi)
                # If combination not yet known
                if combi not in combinations:
                    combinations[combi] = {}
                    combinations[combi]["count"] = 1
                    combinations[combi]["strings"] = []
                    combinations[combi]["strings"].append(string)
                    combinations[combi]["files"] = string_stats[string]["files"]
                else:
                    combinations[combi]["count"] += 1
                    combinations[combi]["strings"].append(string)
                # Set the maximum combination count
                if combinations[combi]["count"] > max_combi_count:
                    max_combi_count = combinations[combi]["count"]
                    # print "Max Combi Count set to: %s" % max_combi_count

    print("[+] Generating Super Rules ... (a lot of foo magic)")
    for combi_count in range(max_combi_count, 1, -1):
        for combi in combinations:
            if combi_count == combinations[combi]["count"]:
                # print "Count %s - Combi %s" % ( str(combinations[combi]["count"]), combi )
                # Filter the string set
                # print "BEFORE"
                # print len(combinations[combi]["strings"])
                # print combinations[combi]["strings"]
                string_set = combinations[combi]["strings"]
                combinations[combi]["strings"] = []
                combinations[combi]["strings"] = filter_string_set(string_set)
                # print combinations[combi]["strings"]
                # print "AFTER"
                # print len(combinations[combi]["strings"])
                # Combi String count after filtering
                # print "String count after filtering: %s" % str(len(combinations[combi]["strings"]))

                # If the string set of the combination has a required size
                if len(combinations[combi]["strings"]) >= int(args.w):
                    # Remove the files in the combi rule from the simple set
                    if args.nosimple:
                        for file in combinations[combi]["files"]:
                            if file in file_strings:
                                del file_strings[file]
                    # Add it as a super rule
                    print("[-] Adding Super Rule with %s strings." % str(len(combinations[combi]["strings"])))
                    # if args.debug:
                    # print "Rule Combi: %s" % combi
                    super_rules.append(combinations[combi])

    # Return all data
    return (file_strings, file_opcodes, combinations, super_rules, inverse_stats)


def filter_opcode_set(opcode_set):
    # Preferred Opcodes
    pref_opcodes = [' 34 ', 'ff ff ff ']

    # Useful set
    useful_set = []
    pref_set = []

    for opcode in opcode_set:
        if opcode in good_opcodes_db:
            continue

        # Format the opcode
        formatted_opcode = get_opcode_string(opcode)

        # Preferred opcodes
        set_in_pref = False
        for pref in pref_opcodes:
            if pref in formatted_opcode:
                pref_set.append(formatted_opcode)
                set_in_pref = True
        if set_in_pref:
            continue

        # Else add to useful set
        useful_set.append(get_opcode_string(opcode))

    # Preferred opcodes first
    useful_set = pref_set + useful_set

    # Only return the number of opcodes defined with the "-n" parameter
    return useful_set[:int(args.n)]


def filter_string_set(string_set):
    # This is the only set we have - even if it's a weak one
    useful_set = []

    # Local string scores
    localStringScores = {}

    # Local UTF strings
    utfstrings = []

    for string in string_set:

        # Goodware string marker
        goodstring = False
        goodcount = 0

        # Goodware Strings
        if string in good_strings_db:
            goodstring = True
            goodcount = good_strings_db[string]
            # print "%s - %s" % ( goodstring, good_strings[string] )
            if args.excludegood:
                continue

        # UTF
        original_string = string
        if string[:8] == "UTF16LE:":
            # print "removed UTF16LE from %s" % string
            string = string[8:]
            utfstrings.append(string)

        # Good string evaluation (after the UTF modification)
        if goodstring:
            # Reduce the score by the number of occurence in goodware files
            localStringScores[string] = (goodcount * -1) + 5
        else:
            localStringScores[string] = 0

        # PEStudio String Blacklist Evaluation
        if pestudio_available:
            (pescore, type) = get_pestudio_score(string)
            # print("PE Match: %s" % string)
            # Reset score of goodware files to 5 if blacklisted in PEStudio
            if type != "":
                pestudioMarker[string] = type
                # Modify the PEStudio blacklisted strings with their goodware stats count
                if goodstring:
                    pescore = pescore - (goodcount / 1000.0)
                    # print "%s - %s - %s" % (string, pescore, goodcount)
                localStringScores[string] = pescore

        if not goodstring:

            # Length Score
            #length = len(string)
            #if length > int(args.y) and length < int(args.s):
            #    localStringScores[string] += round(len(string) / 8, 2)
            #if length >= int(args.s):
            #    localStringScores[string] += 1

            # Reduction
            if ".." in string:
                localStringScores[string] -= 5
            if "   " in string:
                localStringScores[string] -= 5
            # Packer Strings
            if re.search(r'(WinRAR\\SFX)', string):
                localStringScores[string] -= 4
            # US ASCII char
            if "\x1f" in string:
                localStringScores[string] -= 4
            # Chains of 00s
            if string.count('0000000000') > 2:
                localStringScores[string] -= 5
            # Repeated characters
            if re.search(r'(?!.* ([A-Fa-f0-9])\1{8,})', string):
                localStringScores[string] -= 5

            # Certain strings add-ons ----------------------------------------------
            # Extensions - Drive
            if re.search(r'[A-Za-z]:\\', string, re.IGNORECASE):
                localStringScores[string] += 2
            # Relevant file extensions
            if re.search(r'(\.exe|\.pdb|\.scr|\.log|\.cfg|\.txt|\.dat|\.msi|\.com|\.bat|\.dll|\.pdb|\.vbs|'
                         r'\.tmp|\.sys|\.ps1|\.vbp|\.hta|\.lnk)', string, re.IGNORECASE):
                localStringScores[string] += 4
            # System keywords
            if re.search(r'(cmd.exe|system32|users|Documents and|SystemRoot|Grant|hello|password|process|log)',
                         string, re.IGNORECASE):
                localStringScores[string] += 5
            # Protocol Keywords
            if re.search(r'(ftp|irc|smtp|command|GET|POST|Agent|tor2web|HEAD)', string, re.IGNORECASE):
                localStringScores[string] += 5
            # Connection keywords
            if re.search(r'(error|http|closed|fail|version|proxy)', string, re.IGNORECASE):
                localStringScores[string] += 3
            # Browser User Agents
            if re.search(r'(Mozilla|MSIE|Windows NT|Macintosh|Gecko|Opera|User\-Agent)', string, re.IGNORECASE):
                localStringScores[string] += 5
            # Temp and Recycler
            if re.search(r'(TEMP|Temporary|Appdata|Recycler)', string, re.IGNORECASE):
                localStringScores[string] += 4
            # Malicious keywords - hacktools
            if re.search(r'(scan|sniff|poison|intercept|fake|spoof|sweep|dump|flood|inject|forward|scan|vulnerable|'
                         r'credentials|creds|coded|p0c|Content|host)', string, re.IGNORECASE):
                localStringScores[string] += 5
            # Network keywords
            if re.search(r'(address|port|listen|remote|local|process|service|mutex|pipe|frame|key|lookup|connection)',
                         string, re.IGNORECASE):
                localStringScores[string] += 3
            # Drive
            if re.search(r'([C-Zc-z]:\\)', string, re.IGNORECASE):
                localStringScores[string] += 4
            # IP
            if re.search(
                    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
                    string, re.IGNORECASE):  # IP Address
                localStringScores[string] += 5
            # Copyright Owner
            if re.search(r'(coded | c0d3d |cr3w\b|Coded by |codedby)', string, re.IGNORECASE):
                localStringScores[string] += 7
            # Extension generic
            if re.search(r'\.[a-zA-Z]{3}\b', string):
                localStringScores[string] += 3
            # All upper case
            if re.search(r'^[A-Z]{6,}$', string):
                localStringScores[string] += 2.5
            # All lower case
            if re.search(r'^[a-z]{6,}$', string):
                localStringScores[string] += 2
            # All lower with space
            if re.search(r'^[a-z\s]{6,}$', string):
                localStringScores[string] += 2
            # All characters
            if re.search(r'^[A-Z][a-z]{5,}$', string):
                localStringScores[string] += 2
            # URL
            if re.search(r'(%[a-z][:\-,;]|\\\\%s|\\\\[A-Z0-9a-z%]+\\[A-Z0-9a-z%]+)', string):
                localStringScores[string] += 2.5
            # certificates
            if re.search(r'(thawte|trustcenter|signing|class|crl|CA|certificate|assembly)', string, re.IGNORECASE):
                localStringScores[string] -= 4
            # Parameters
            if re.search(r'( \-[a-z]{,2}[\s]?[0-9]?| /[a-z]+[\s]?[\w]*)', string, re.IGNORECASE):
                localStringScores[string] += 4
            # Directory
            if re.search(r'([a-zA-Z]:|^|%)\\[A-Za-z]{4,30}\\', string):
                localStringScores[string] += 4
            # Executable - not in directory
            if re.search(r'^[^\\]+\.(exe|com|scr|bat|sys)$', string, re.IGNORECASE):
                localStringScores[string] += 4
            # Date placeholders
            if re.search(r'(yyyy|hh:mm|dd/mm|mm/dd|%s:%s:)', string, re.IGNORECASE):
                localStringScores[string] += 3
            # Placeholders
            if re.search(r'[^A-Za-z](%s|%d|%i|%02d|%04d|%2d|%3s)[^A-Za-z]', string, re.IGNORECASE):
                localStringScores[string] += 3
            # String parts from file system elements
            if re.search(r'(cmd|com|pipe|tmp|temp|recycle|bin|secret|private|AppData|driver|config)', string,
                         re.IGNORECASE):
                localStringScores[string] += 3
            # Programming
            if re.search(r'(execute|run|system|shell|root|cimv2|login|exec|stdin|read|process|netuse|script|share)',
                         string, re.IGNORECASE):
                localStringScores[string] += 3
            # Credentials
            if re.search(r'(user|pass|login|logon|token|cookie|creds|hash|ticket|NTLM|LMHASH|kerberos|spnego|session|'
                         r'identif|account|login|auth|privilege)', string, re.IGNORECASE):
                localStringScores[string] += 3
            # Malware
            if re.search(r'(\.[a-z]/[^/]+\.txt|)', string, re.IGNORECASE):
                localStringScores[string] += 3
            # Variables
            if re.search(r'%[A-Z_]+%', string, re.IGNORECASE):
                localStringScores[string] += 4
            # RATs / Malware
            if re.search(r'(spy|logger|dark|cryptor|RAT\b|eye|comet|evil|xtreme|poison|meterpreter|metasploit|/veil|Blood)',
                         string, re.IGNORECASE):
                localStringScores[string] += 5
            # Missed user profiles
            if re.search(r'[\\](users|profiles|username|benutzer|Documents and Settings|Utilisateurs|Utenti|'
                         r'Usuários)[\\]', string, re.IGNORECASE):
                localStringScores[string] += 3
            # Strings: Words ending with numbers
            if re.search(r'^[A-Z][a-z]+[0-9]+$', string, re.IGNORECASE):
                localStringScores[string] += 1
            # Spying
            if re.search(r'(implant)', string, re.IGNORECASE):
                localStringScores[string] += 1
            # Program Path - not Programs or Windows
            if re.search(r'^[Cc]:\\\\[^PW]', string):
                localStringScores[string] += 3
            # Special strings
            if re.search(r'(\\\\\.\\|kernel|.dll|usage|\\DosDevices\\)', string, re.IGNORECASE):
                localStringScores[string] += 5
            # Parameters
            if re.search(r'( \-[a-z] | /[a-z] | \-[a-z]:[a-zA-Z]| \/[a-z]:[a-zA-Z])', string):
                localStringScores[string] += 4
            # File
            if re.search(r'^[a-zA-Z0-9]{3,40}\.[a-zA-Z]{3}', string, re.IGNORECASE):
                localStringScores[string] += 3
            # Comment Line / Output Log
            if re.search(r'^([\*\#]+ |\[[\*\-\+]\] |[\-=]> |\[[A-Za-z]\] )', string):
                localStringScores[string] += 4
            # Output typo / special expression
            if re.search(r'(!\.$|!!!$| :\)$| ;\)$|fucked|[\w]\.\.\.\.$)', string):
                localStringScores[string] += 4
            # Base64
            if re.search(r'^(?:[A-Za-z0-9+/]{4}){30,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$', string) and \
                    re.search(r'[A-Za-z]', string) and re.search(r'[0-9]', string):
                localStringScores[string] += 6
            # Base64 Executables
            if re.search(r'(TVqQAAMAAAAEAAAA//8AALgAAAA|TVpQAAIAAAAEAA8A//8AALgAAAA|TVqAAAEAAAAEABAAAAAAAAAAAAA|'
                         r'TVoAAAAAAAAAAAAAAAAAAAAAAAA|TVpTAQEAAAAEAAAA//8AALgAAAA)', string):
                localStringScores[string] += 5
            # Malicious intent
            if re.search(r'(loader|cmdline|ntlmhash|lmhash|infect|encrypt|exec|elevat|dump|target|victim|override|'
                         r'traverse|mutex|pawnde|exploited|shellcode|injected|spoofed|dllinjec|exeinj|reflective|'
                         r'payload|inject|back conn)',
                         string, re.IGNORECASE):
                localStringScores[string] += 5
            # Privileges
            if re.search(r'(administrator|highest|system|debug|dbg|admin|adm|root) privilege', string, re.IGNORECASE):
                localStringScores[string] += 4
            # System file/process names
            if re.search(r'(LSASS|SAM|lsass.exe|cmd.exe|LSASRV.DLL)', string):
                localStringScores[string] += 4
            # System file/process names
            if re.search(r'(\.exe|\.dll|\.sys)$', string, re.IGNORECASE):
                localStringScores[string] += 4
            # Indicators that string is valid
            if re.search(r'(^\\\\)', string, re.IGNORECASE):
                localStringScores[string] += 1
            # Compiler output directories
            if re.search(r'(\\Release\\|\\Debug\\|\\bin|\\sbin)', string, re.IGNORECASE):
                localStringScores[string] += 2
            # Special - Malware related strings
            if re.search(r'(Management Support Team1|/c rundll32|DTOPTOOLZ Co.|net start|Exec|taskkill)', string):
                localStringScores[string] += 4
            # Powershell
            if re.search(r'(bypass|windowstyle | hidden |-command|IEX |Invoke-Expression|Net.Webclient|Invoke[A-Z]|'
                         r'Net.WebClient|-w hidden |-encoded'
                         r'-encodedcommand| -nop |MemoryLoadLibrary|FromBase64String|Download|EncodedCommand)', string, re.IGNORECASE):
                localStringScores[string] += 4
            # WMI
            if re.search(r'( /c WMIC)', string, re.IGNORECASE):
                localStringScores[string] += 3
            # Windows Commands
            if re.search(r'( net user | net group |ping |whoami |bitsadmin |rundll32.exe javascript:|'
                         r'schtasks.exe /create|/c start )',
                         string, re.IGNORECASE):
                localStringScores[string] += 3
            # JavaScript
            if re.search(r'(new ActiveXObject\("WScript.Shell"\).Run|.Run\("cmd.exe|.Run\("%comspec%\)|'
                         r'.Run\("c:\\Windows|.RegisterXLL\()', string, re.IGNORECASE):
                localStringScores[string] += 3
            # Signing Certificates
            if re.search(r'( Inc | Co.|  Ltd.,| LLC| Limited)', string):
                localStringScores[string] += 2
            # Privilege escalation
            if re.search(r'(sysprep|cryptbase|secur32)', string, re.IGNORECASE):
                localStringScores[string] += 2
            # Webshells
            if re.search(r'(isset\($post\[|isset\($get\[|eval\(Request)', string, re.IGNORECASE):
                localStringScores[string] += 2
            # Suspicious words 1
            if re.search(r'(impersonate|drop|upload|download|execute|shell|\bcmd\b|decode|rot13|decrypt)', string,
                         re.IGNORECASE):
                localStringScores[string] += 2
            # Suspicious words 1
            if re.search(r'([+] |[-] |[*] |injecting|exploit|dumped|dumping|scanning|scanned|elevation|'
                         r'elevated|payload|vulnerable|payload|reverse connect|bind shell|reverse shell| dump | '
                         r'back connect |privesc|privilege escalat|debug privilege| inject |interactive shell|'
                         r'shell commands| spawning |] target |] Transmi|] Connect|] connect|] Dump|] command |'
                         r'] token|] Token |] Firing | hashes | etc/passwd| SAM | NTML|unsupported target|'
                         r'race condition|Token system |LoaderConfig| add user |ile upload |ile download |'
                         r'Attaching to |ser has been successfully added|target system |LSA Secrets|DefaultPassword|'
                         r'Password: |loading dll|.Execute\(|Shellcode|Loader|inject x86|inject x64|bypass|katz|'
                         r'sploit|ms[0-9][0-9][^0-9]|\bCVE[^a-zA-Z]|privilege::|lsadump|door)',
                         string, re.IGNORECASE):
                localStringScores[string] += 4
            # Mutex / Named Pipes
            if re.search(r'(Mutex|NamedPipe|\\Global\\|\\pipe\\)', string, re.IGNORECASE):
                localStringScores[string] += 3
            # Usage
            if re.search(r'(isset\($post\[|isset\($get\[)', string, re.IGNORECASE):
                localStringScores[string] += 2
            # Hash
            if re.search(r'\b([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b', string, re.IGNORECASE):
                localStringScores[string] += 2
            # Persistence
            if re.search(r'(sc.exe |schtasks|at \\\\|at [0-9]{2}:[0-9]{2})', string, re.IGNORECASE):
                localStringScores[string] += 3
            # Unix/Linux
            if re.search(r'(;chmod |; chmod |sh -c|/dev/tcp/|/bin/telnet|selinux| shell| cp /bin/sh )', string,
                         re.IGNORECASE):
                localStringScores[string] += 3
            # Attack
            if re.search(
                    r'(attacker|brute force|bruteforce|connecting back|EXHAUSTIVE|exhaustion| spawn| evil| elevated)',
                    string, re.IGNORECASE):
                localStringScores[string] += 3
            # Strings with less value
            if re.search(r'(abcdefghijklmnopqsst|ABCDEFGHIJKLMNOPQRSTUVWXYZ|0123456789:;)', string, re.IGNORECASE):
                localStringScores[string] -= 5
            # VB Backdoors
            if re.search(
                    r'(kill|wscript|plugins|svr32|Select |)',
                    string, re.IGNORECASE):
                localStringScores[string] += 3
            # Suspicious strings - combo / special characters
            if re.search(
                    r'([a-z]{4,}[!\?]|\[[!+\-]\] |[a-zA-Z]{4,}...)',
                    string, re.IGNORECASE):
                localStringScores[string] += 3
            if re.search(
                    r'(-->|!!!| <<< | >>> )',
                    string, re.IGNORECASE):
                localStringScores[string] += 5
            # Swear words
            if re.search(
                    r'\b(fuck|damn|shit|penis)\b',
                    string, re.IGNORECASE):
                localStringScores[string] += 5
            # Scripting Strings
            if re.search(
                    r'(%APPDATA%|%USERPROFILE%|Public|Roaming|& del|& rm| && |script)',
                    string, re.IGNORECASE):
                localStringScores[string] += 3
            # UACME Bypass
            if re.search(
                    r'(Elevation|pwnd|pawn|elevate to)',
                    string, re.IGNORECASE):
                localStringScores[string] += 3

            # ENCODING DETECTIONS --------------------------------------------------
            try:
                if len(string) > 8:
                    # Try different ways - fuzz string
                    # Base64
                    if args.trace:
                        print("Starting Base64 string analysis ...")
                    for m_string in (string, string[1:], string[1:] + "=", string + "=", string + "=="):
                        if is_base_64(m_string):
                            decoded_string = m_string.decode('base64')
                            # print decoded_string
                            if is_ascii_string(decoded_string, padding_allowed=True):
                                # print "match"
                                localStringScores[string] += 10
                                base64strings[string] = decoded_string
                    # Hex Encoded string
                    if args.trace:
                        print("Starting Hex encoded string analysis ...")
                    for m_string in ([string, re.sub('[^a-zA-Z0-9]', '', string)]):
                        #print m_string
                        if is_hex_encoded(m_string):
                            #print("^ is HEX")
                            decoded_string = m_string.decode('hex')
                            #print removeNonAsciiDrop(decoded_string)
                            if is_ascii_string(decoded_string, padding_allowed=True):
                                # not too many 00s
                                if '00' in m_string:
                                    if len(m_string) / float(m_string.count('0')) <= 1.2:
                                        continue
                                #print("^ is ASCII / WIDE")
                                localStringScores[string] += 8
                                hexEncStrings[string] = decoded_string
            except Exception as e:
                if args.debug:
                    traceback.print_exc()
                pass

            # Reversed String -----------------------------------------------------
            if string[::-1] in good_strings_db:
                localStringScores[string] += 10
                reversedStrings[string] = string[::-1]

            # Certain string reduce	-----------------------------------------------
            if re.search(r'(rundll32\.exe$|kernel\.dll$)', string, re.IGNORECASE):
                localStringScores[string] -= 4

        # Set the global string score
        stringScores[original_string] = localStringScores[string]

        if args.debug:
            if string in utfstrings:
                is_utf = True
            else:
                is_utf = False
                # print "SCORE: %s\tUTF: %s\tSTRING: %s" % ( localStringScores[string], is_utf, string )

    sorted_set = sorted(localStringScores.iteritems(), key=operator.itemgetter(1), reverse=True)

    # Only the top X strings
    c = 0
    result_set = []
    for string in sorted_set:

        # Skip the one with a score lower than -z X
        if not args.noscorefilter and not args.inverse:
            if string[1] < int(args.z):
                continue

        if string[0] in utfstrings:
            result_set.append("UTF16LE:%s" % string[0])
        else:
            result_set.append(string[0])

        #c += 1
        #if c > int(args.rc):
        #    break

    if args.trace:
        print("RESULT SET:")
        print(result_set)

    # return the filtered set
    return result_set


def generate_general_condition(file_info):
    """
    Generates a general condition for a set of files
    :param file_info:
    :return:
    """
    conditions_string = ""
    conditions = []
    pe_module_neccessary = False

    # Different Magic Headers and File Sizes
    magic_headers = []
    file_sizes = []
    imphashes = []

    try:
        for filePath in file_info:
            # Short file name info used for inverse generation has no magic/size fields
            if "magic" not in file_info[filePath]:
                continue
            magic = file_info[filePath]["magic"]
            size = file_info[filePath]["size"]
            imphash = file_info[filePath]["imphash"]

            # Add them to the lists
            if magic not in magic_headers and magic != "":
                magic_headers.append(magic)
            if size not in file_sizes:
                file_sizes.append(size)
            if imphash not in imphashes and imphash != "":
                imphashes.append(imphash)

        # If different magic headers are less than 5
        if len(magic_headers) <= 5:
            magic_string = " or ".join(get_uint_string(h) for h in magic_headers)
            if " or " in magic_string:
                conditions.append("( {0} )".format(magic_string))
            else:
                conditions.append("{0}".format(magic_string))

        # Biggest size multiplied with maxsize_multiplier
        if not args.nofilesize and len(file_sizes) > 0:
            conditions.append(get_file_range(max(file_sizes)))

        # If different magic headers are less than 5
        if len(imphashes) == 1:
            conditions.append("pe.imphash() == \"{0}\"".format(imphashes[0]))
            pe_module_neccessary = True

        # If enough attributes were special
        condition_string = " and ".join(conditions)

    except Exception as e:
        if args.debug:
            traceback.print_exc()
            exit(1)
        print("[E] ERROR while generating general condition - check the global rule and remove it if it's faulty")

    return condition_string, pe_module_neccessary


def generate_rules(file_strings, file_opcodes, super_rules, file_info, inverse_stats):
    # Write to file ---------------------------------------------------
    if args.o:
        try:
            fh = open(args.o, 'w')
        except Exception as e:
            traceback.print_exc()

    # General Info
    general_info = "/*\n"
    general_info += "   YARA Rule Set\n"
    general_info += "   Author: {0}\n".format(args.a)
    general_info += "   Date: {0}\n".format(get_timestamp_basic())
    general_info += "   Identifier: {0}\n".format(identifier)
    general_info += "   Reference: {0}\n".format(reference)
    if args.l != "":
        general_info += "   License: {0}\n".format(args.l)
    general_info += "*/\n\n"

    fh.write(general_info)

    # GLOBAL RULES ----------------------------------------------------
    if args.globalrule:

        condition, pe_module_necessary = generate_general_condition(file_info)

        # Global Rule
        if condition != "":
            global_rule = "/* Global Rule -------------------------------------------------------------- */\n"
            global_rule += "/* Will be evaluated first, speeds up scanning process, remove at will */\n\n"
            global_rule += "global private rule gen_characteristics {\n"
            global_rule += "   condition:\n"
            global_rule += "      {0}\n".format(condition)
            global_rule += "}\n\n"

            # Write rule
            if args.o:
                fh.write(global_rule)

    # General vars
    rules = ""
    printed_rules = {}
    opcodes_to_add = []
    rule_count = 0
    inverse_rule_count = 0
    super_rule_count = 0
    pe_module_necessary = False

    if not args.inverse:
        # PROCESS SIMPLE RULES ----------------------------------------------------
        print("[+] Generating Simple Rules ...")
        # Apply intelligent filters
        print("[-] Applying intelligent filters to string findings ...")
        for filePath in file_strings:

            print("[-] Filtering string set for %s ..." % filePath)

            # Replace the original string set with the filtered one
            string_set = file_strings[filePath]
            file_strings[filePath] = []
            file_strings[filePath] = filter_string_set(string_set)

            # Replace the original string set with the filtered one
            if filePath not in file_opcodes:
                file_opcodes[filePath] = []
            else:
                print("[-] Filtering opcode set for %s ..." % filePath)
            opcode_set = file_opcodes[filePath]
            file_opcodes[filePath] = []
            file_opcodes[filePath] = filter_opcode_set(opcode_set)

        # GENERATE SIMPLE RULES -------------------------------------------
        fh.write("/* Rule Set ----------------------------------------------------------------- */\n\n")

        for filePath in file_strings:

            # Skip if there is nothing to do
            if len(file_strings[filePath]) == 0:
                print("[W] Not enough high scoring strings to create a rule. "
                      "(Try -z 0 to reduce the min score or --opcodes to include opcodes) FILE: %s" % filePath)
                continue
            elif len(file_strings[filePath]) == 0 and len(file_opcodes[filePath]) == 0:
                print("[W] Not enough high scoring strings and opcodes to create a rule. " \
                      "(Try -z 0 to reduce the min score) FILE: %s" % filePath)
                continue

            # Create Rule
            try:
                rule = ""
                (path, file) = os.path.split(filePath)
                # Prepare name
                fileBase = os.path.splitext(file)[0]
                # Create a clean new name
                cleanedName = fileBase
                # Adapt length of rule name
                if len(fileBase) < 8:  # if name is too short add part from path
                    cleanedName = path.split('\\')[-1:][0] + "_" + cleanedName
                # File name starts with a number
                if re.search(r'^[0-9]', cleanedName):
                    cleanedName = "sig_" + cleanedName
                # clean name from all characters that would cause errors
                cleanedName = re.sub('[^\w]', r'_', cleanedName)
                # Check if already printed
                if cleanedName in printed_rules:
                    printed_rules[cleanedName] += 1
                    cleanedName = cleanedName + "_" + str(printed_rules[cleanedName])
                else:
                    printed_rules[cleanedName] = 1

                # Print rule title ----------------------------------------
                rule += "rule %s {\n" % cleanedName

                # Meta data -----------------------------------------------
                rule += "   meta:\n"
                rule += "      description = \"%s - file %s\"\n" % (prefix, file)
                rule += "      author = \"%s\"\n" % args.a
                rule += "      reference = \"%s\"\n" % reference
                rule += "      date = \"%s\"\n" % get_timestamp_basic()
                rule += "      hash1 = \"%s\"\n" % file_info[filePath]["hash"]
                rule += "   strings:\n"

                # Get the strings -----------------------------------------
                # Rule String generation
                (rule_strings, opcodes_included, string_rule_count, high_scoring_strings) = \
                    get_rule_strings(file_strings[filePath], file_opcodes[filePath])
                rule += rule_strings

                # Extract rul strings
                if args.strings:
                    strings = get_strings(file_strings[filePath])
                    write_strings(filePath, strings, args.e, args.score)

                # Condition -----------------------------------------------
                # Conditions list (will later be joined with 'or')
                conditions = []  # AND connected
                subconditions = []  # OR connected

                # Condition PE
                # Imphash and Exports - applicable to PE files only
                condition_pe = []
                condition_pe_part1 = []
                condition_pe_part2 = []
                if not args.noextras and file_info[filePath]["magic"] == "MZ":
                    # Add imphash - if certain conditions are met
                    if file_info[filePath]["imphash"] not in good_imphashes_db and file_info[filePath]["imphash"] != "":
                        # Comment to imphash
                        imphash = file_info[filePath]["imphash"]
                        comment = ""
                        if imphash in KNOWN_IMPHASHES:
                            comment = " /* {0} */".format(KNOWN_IMPHASHES[imphash])
                        # Add imphash to condition
                        condition_pe_part1.append("pe.imphash() == \"{0}\"{1}".format(imphash, comment))
                        pe_module_necessary = True
                    if file_info[filePath]["exports"]:
                        e_count = 0
                        for export in file_info[filePath]["exports"]:
                            if export not in good_exports_db:
                                condition_pe_part2.append("pe.exports(\"{0}\")".format(export))
                                e_count += 1
                                pe_module_necessary = True
                            if e_count > 5:
                                break

                # 1st Part of Condition 1
                basic_conditions = []
                # Filesize
                if not args.nofilesize:
                    basic_conditions.insert(0, get_file_range(file_info[filePath]["size"]))
                # Magic
                if file_info[filePath]["magic"] != "":
                    uint_string = get_uint_string(file_info[filePath]["magic"])
                    basic_conditions.insert(0, uint_string)
                # Basic Condition
                if len(basic_conditions):
                    conditions.append(" and ".join(basic_conditions))

                # Add extra PE conditions to condition 1
                pe_conditions_add = False
                if condition_pe_part1 or condition_pe_part2:
                    if len(condition_pe_part1) == 1:
                        condition_pe.append(condition_pe_part1[0])
                    elif len(condition_pe_part1) > 1:
                        condition_pe.append("( %s )" % " or ".join(condition_pe_part1))
                    if len(condition_pe_part2) == 1:
                        condition_pe.append(condition_pe_part2[0])
                    elif len(condition_pe_part2) > 1:
                        condition_pe.append("( %s )" % " and ".join(condition_pe_part2))
                    # Marker that PE conditions have been added
                    pe_conditions_add = True
                    # Add to sub condition
                    subconditions.append(" and ".join(condition_pe))

                # String combinations
                cond_op = ""  # opcodes condition
                cond_hs = ""  # high scoring strings condition
                cond_ls = ""  # low scoring strings condition

                low_scoring_strings = (string_rule_count - high_scoring_strings)
                if high_scoring_strings > 0:
                    cond_hs = "1 of ($x*)"
                if low_scoring_strings > 0:
                    if low_scoring_strings > 10:
                        if high_scoring_strings > 0:
                            cond_ls = "4 of them"
                        else:
                            cond_ls = "8 of them"
                    else:
                        cond_ls = "all of them"

                # If low scoring and high scoring
                cond_combined = "all of them"
                needs_brackets = False
                if low_scoring_strings > 0 and high_scoring_strings > 0:
                    # If PE conditions have been added, don't be so strict with the strings
                    if pe_conditions_add:
                        cond_combined = "{0} or {1}".format(cond_hs, cond_ls)
                        needs_brackets = True
                    else:
                        cond_combined = "{0} and {1}".format(cond_hs, cond_ls)
                elif low_scoring_strings > 0 and not high_scoring_strings > 0:
                    cond_combined = "{0}".format(cond_ls)
                elif not low_scoring_strings > 0 and high_scoring_strings > 0:
                    cond_combined = "{0}".format(cond_hs)
                if opcodes_included:
                    cond_op = " and all of ($op*)"

                # Opcodes (if needed)
                if cond_op or needs_brackets:
                    subconditions.append("( {0}{1} )".format(cond_combined, cond_op))
                else:
                    subconditions.append(cond_combined)

                # Now add string condition to the conditions
                if len(subconditions) == 1:
                    conditions.append(subconditions[0])
                elif len(subconditions) > 1:
                    conditions.append("( %s )" % " or ".join(subconditions))

                # Create condition string
                condition_string = " and\n      ".join(conditions)

                rule += "   condition:\n"
                rule += "      %s\n" % condition_string
                rule += "}\n\n"

                # Add to rules string
                rules += rule

                rule_count += 1
            except Exception as e:
                traceback.print_exc()

    # GENERATE SUPER RULES --------------------------------------------
    if not nosuper and not args.inverse:

        rules += "/* Super Rules ------------------------------------------------------------- */\n\n"
        super_rule_names = []

        print("[+] Generating Super Rules ...")
        printed_combi = {}
        for super_rule in super_rules:
            try:
                rule = ""
                # Prepare Name
                rule_name = ""
                file_list = []

                # Loop through files
                imphashes = Counter()
                for filePath in super_rule["files"]:
                    (path, file) = os.path.split(filePath)
                    file_list.append(file)
                    # Prepare name
                    fileBase = os.path.splitext(file)[0]
                    # Create a clean new name
                    cleanedName = fileBase
                    # Append it to the full name
                    rule_name += "_" + cleanedName
                    # Check if imphash of all files is equal
                    imphash = file_info[filePath]["imphash"]
                    if imphash != "-" and imphash != "":
                        imphashes.update([imphash])

                # Imphash usable
                if len(imphashes) == 1:
                    unique_imphash = imphashes.items()[0][0]
                    if unique_imphash in good_imphashes_db:
                        unique_imphash = ""

                # Shorten rule name
                rule_name = rule_name[:124]
                # Add count if rule name already taken
                if rule_name not in super_rule_names:
                    rule_name = "%s_%s" % (rule_name, super_rule_count)
                super_rule_names.append(rule_name)

                # Create a list of files
                file_listing = ", ".join(file_list)

                # File name starts with a number
                if re.search(r'^[0-9]', rule_name):
                    rule_name = "sig_" + rule_name
                # clean name from all characters that would cause errors
                rule_name = re.sub('[^\w]', r'_', rule_name)
                # Check if already printed
                if rule_name in printed_rules:
                    printed_combi[rule_name] += 1
                    rule_name = rule_name + "_" + str(printed_combi[rule_name])
                else:
                    printed_combi[rule_name] = 1

                # Print rule title
                rule += "rule %s {\n" % rule_name
                rule += "   meta:\n"
                rule += "      description = \"%s - from files %s\"\n" % (prefix, file_listing)
                rule += "      author = \"%s\"\n" % args.a
                rule += "      reference = \"%s\"\n" % reference
                rule += "      date = \"%s\"\n" % get_timestamp_basic()
                for i, filePath in enumerate(super_rule["files"]):
                    rule += "      hash%s = \"%s\"\n" % (str(i + 1), file_info[filePath]["hash"])

                rule += "   strings:\n"

                # Adding the strings
                if file_opcodes.get(filePath) is None:
                    tmp_file_opcodes = {}
                else:
                    tmp_file_opcodes = file_opcodes.get(filePath)
                (rule_strings, opcodes_included, string_rule_count, high_scoring_strings) = \
                    get_rule_strings(super_rule["strings"], tmp_file_opcodes)
                rule += rule_strings

                # Condition -----------------------------------------------
                # Conditions list (will later be joined with 'or')
                conditions = []

                # 1st condition
                # Evaluate the general characteristics
                file_info_super = {}
                for filePath in super_rule["files"]:
                    file_info_super[filePath] = file_info[filePath]
                condition_strings, pe_module_necessary_gen = generate_general_condition(file_info_super)
                if pe_module_necessary_gen:
                     pe_module_necessary = True

                # 2nd condition
                # String combinations
                cond_op = ""  # opcodes condition
                cond_hs = ""  # high scoring strings condition
                cond_ls = ""  # low scoring strings condition

                low_scoring_strings = (string_rule_count - high_scoring_strings)
                if high_scoring_strings > 0:
                    cond_hs = "1 of ($x*)"
                if low_scoring_strings > 0:
                    if low_scoring_strings > 10:
                        if high_scoring_strings > 0:
                            cond_ls = "4 of them"
                        else:
                            cond_ls = "8 of them"
                    else:
                        cond_ls = "all of them"

                # If low scoring and high scoring
                cond_combined = "all of them"
                if low_scoring_strings > 0 and high_scoring_strings > 0:
                    cond_combined = "{0} and {1}".format(cond_hs, cond_ls)
                elif low_scoring_strings > 0 and not high_scoring_strings > 0:
                    cond_combined = "{0}".format(cond_ls)
                elif not low_scoring_strings > 0 and high_scoring_strings > 0:
                    cond_combined = "{0}".format(cond_hs)
                if opcodes_included:
                    cond_op = " and all of ($op*)"

                condition2 = "( {0} ){1}".format(cond_combined, cond_op)
                conditions.append(" and ".join([condition_strings, condition2]))

                # 3nd condition
                # In memory detection base condition (no magic, no filesize)
                condition_pe = "all of them"
                conditions.append(condition_pe)

                # Create condition string
                condition_string = "\n      ) or ( ".join(conditions)

                rule += "   condition:\n"
                rule += "      ( %s )\n" % condition_string
                rule += "}\n\n"

                # print rule
                # Add to rules string
                rules += rule

                super_rule_count += 1
            except Exception as e:
                traceback.print_exc()

    try:
        # WRITING RULES TO FILE
        # PE Module -------------------------------------------------------
        if not args.noextras:
            if pe_module_necessary:
                fh.write('import "pe"\n\n')
        # RULES -----------------------------------------------------------
        if args.o:
            fh.write(rules)
    except Exception as e:
        traceback.print_exc()

    # PROCESS INVERSE RULES ---------------------------------------------------
    # print inverse_stats.keys()
    if args.inverse:
        print("[+] Generating inverse rules ...")
        inverse_rules = ""
        # Apply intelligent filters -------------------------------------------
        print("[+] Applying intelligent filters to string findings ...")
        for fileName in inverse_stats:

            print("[-] Filtering string set for %s ..." % fileName)

            # Replace the original string set with the filtered one
            string_set = inverse_stats[fileName]
            inverse_stats[fileName] = []
            inverse_stats[fileName] = filter_string_set(string_set)

            # Preset if empty
            if fileName not in file_opcodes:
                file_opcodes[fileName] = {}

        # GENERATE INVERSE RULES -------------------------------------------
        fh.write("/* Inverse Rules ------------------------------------------------------------- */\n\n")

        for fileName in inverse_stats:
            try:
                rule = ""
                # Create a clean new name
                cleanedName = fileName.replace(".", "_")
                # Add ANOMALY
                cleanedName += "_ANOMALY"
                # File name starts with a number
                if re.search(r'^[0-9]', cleanedName):
                    cleanedName = "sig_" + cleanedName
                # clean name from all characters that would cause errors
                cleanedName = re.sub('[^\w]', r'_', cleanedName)
                # Check if already printed
                if cleanedName in printed_rules:
                    printed_rules[cleanedName] += 1
                    cleanedName = cleanedName + "_" + str(printed_rules[cleanedName])
                else:
                    printed_rules[cleanedName] = 1

                # Print rule title ----------------------------------------
                rule += "rule %s {\n" % cleanedName

                # Meta data -----------------------------------------------
                rule += "   meta:\n"
                rule += "      description = \"%s for anomaly detection - file %s\"\n" % (prefix, fileName)
                rule += "      author = \"%s\"\n" % args.a
                rule += "      reference = \"%s\"\n" % reference
                rule += "      date = \"%s\"\n" % get_timestamp_basic()
                for i, hash in enumerate(file_info[fileName]["hashes"]):
                    rule += "      hash%s = \"%s\"\n" % (str(i + 1), hash)

                rule += "   strings:\n"

                # Get the strings -----------------------------------------
                # Rule String generation
                (rule_strings, opcodes_included, string_rule_count, high_scoring_strings) = \
                    get_rule_strings(inverse_stats[fileName], file_opcodes[fileName])
                rule += rule_strings

                # Condition -----------------------------------------------
                folderNames = ""
                if not args.nodirname:
                    folderNames += "and ( filepath matches /"
                    folderNames += "$/ or filepath matches /".join(file_info[fileName]["folder_names"])
                    folderNames += "$/ )"
                condition = "filename == \"%s\" %s and not ( all of them )" % (fileName, folderNames)

                rule += "   condition:\n"
                rule += "      %s\n" % condition
                rule += "}\n\n"

                # print rule
                # Add to rules string
                inverse_rules += rule

            except Exception as e:
                traceback.print_exc()

        try:
            # Try to write rule to file
            if args.o:
                fh.write(inverse_rules)
            inverse_rule_count += 1
        except Exception as e:
            traceback.print_exc()

    # Close the rules file --------------------------------------------
    if args.o:
        try:
            fh.close()
        except Exception as e:
            traceback.print_exc()

    # Print rules to command line -------------------------------------
    if args.debug:
        print(rules)

    return (rule_count, inverse_rule_count, super_rule_count)


def get_rule_strings(string_elements, opcode_elements):
    rule_strings = ""
    high_scoring_strings = 0
    string_rule_count = 0

    # Adding the strings --------------------------------------
    for i, string in enumerate(string_elements):

        # Collect the data
        is_fullword = True
        initial_string = string
        enc = " ascii"
        base64comment = ""
        hexEncComment = ""
        reversedComment = ""
        fullword = ""
        pestudio_comment = ""
        score_comment = ""
        goodware_comment = ""

        if string in good_strings_db:
            goodware_comment = " /* Goodware String - occured %s times */" % (good_strings_db[string])

        if string in stringScores:
            if args.score:
                score_comment += " /* score: '%.2f'*/" % (stringScores[string])
        else:
            print("NO SCORE: %s" % string)

        if string[:8] == "UTF16LE:":
            string = string[8:]
            enc = " wide"
        if string in base64strings:
            base64comment = " /* base64 encoded string '%s' */" % base64strings[string]
        if string in hexEncStrings:
            hexEncComment = " /* hex encoded string '%s' */" % removeNonAsciiDrop(hexEncStrings[string])
        if string in pestudioMarker and args.score:
            pestudio_comment = " /* PEStudio Blacklist: %s */" % pestudioMarker[string]
        if string in reversedStrings:
            reversedComment = " /* reversed goodware string '%s' */" % reversedStrings[string]

        # Extra checks
        if is_hex_encoded(string, check_length=False):
            is_fullword = False

        # Checking string length
        if len(string) >= args.s:
            # cut string
            string = string[:args.s].rstrip("\\")
            # not fullword anymore
            is_fullword = False
        # Show as fullword
        if is_fullword:
            fullword = " fullword"

        # Now compose the rule line
        if float(stringScores[initial_string]) > score_highly_specific:
            high_scoring_strings += 1
            rule_strings += "      $x%s = \"%s\"%s%s%s%s%s%s%s%s\n" % (
            str(i + 1), string, fullword, enc, base64comment, reversedComment, pestudio_comment, score_comment,
            goodware_comment, hexEncComment)
        else:
            rule_strings += "      $s%s = \"%s\"%s%s%s%s%s%s%s%s\n" % (
            str(i + 1), string, fullword, enc, base64comment, reversedComment, pestudio_comment, score_comment,
            goodware_comment, hexEncComment)

        # If too many string definitions found - cut it at the
        # count defined via command line param -rc
        if (i + 1) >= int(args.rc):
            break

        string_rule_count += 1

    # If too few strings - add opcodes
    # Adding the strings --------------------------------------
    opcodes_included = False
    if len(opcode_elements) > 0:
        rule_strings += "\n"
        for i, opcode in enumerate(opcode_elements):
            rule_strings += "      $op%s = { %s }\n" % (str(i), opcode)
            opcodes_included = True
    else:
        if args.opcodes:
            print("[-] Not enough unique opcodes found to include them")

    return rule_strings, opcodes_included, string_rule_count, high_scoring_strings


def get_strings(string_elements):
    """
    Get a dictionary of all string types
    :param string_elements:
    :return:
    """
    strings = {
        "ascii": [],
        "wide": [],
        "base64 encoded": [],
        "hex encoded": [],
        "reversed": []
    }

    # Adding the strings --------------------------------------
    for i, string in enumerate(string_elements):

        if string[:8] == "UTF16LE:":
            string = string[8:]
            strings["wide"].append(string)
        elif string in base64strings:
            strings["base64 encoded"].append(string)
        elif string in hexEncStrings:
            strings["hex encoded"].append(string)
        elif string in reversedStrings:
            strings["reversed"].append(string)
        else:
            strings["ascii"].append(string)

    return strings


def write_strings(filePath, strings, output_dir, scores):
    """
    Writes string information to an output file
    :param filePath:
    :param strings:
    :param output_dir:
    :param scores:
    :return:
    """
    SECTIONS = ["ascii", "wide", "base64 encoded", "hex encoded", "reversed"]
    # File
    filename = os.path.basename(filePath)
    strings_filename = os.path.join(output_dir, "%s_strings.txt" % filename)
    print("[+] Writing strings to file %s" % strings_filename)
    # Strings
    output_string = []
    for key in SECTIONS:
        # Skip empty
        if len(strings[key]) < 1:
            continue
        # Section
        output_string.append("%s Strings" % key.upper())
        output_string.append("------------------------------------------------------------------------")
        for string in strings[key]:
            if scores:
                score = "unknown"
                if key == "wide":
                    score = stringScores["UTF16LE:%s" % string]
                else:
                    score = stringScores[string]
                output_string.append("%d;%s" % score, string)
            else:
                output_string.append(string)
        # Empty line between sections
        output_string.append("\n")
    with open(strings_filename, "w") as fh:
        fh.write("\n".join(output_string))


def initialize_pestudio_strings():
    pestudio_strings = {}

    tree = etree.parse(get_abs_path(PE_STRINGS_FILE))

    pestudio_strings["strings"] = tree.findall(".//string")
    pestudio_strings["av"] = tree.findall(".//av")
    pestudio_strings["folder"] = tree.findall(".//folder")
    pestudio_strings["os"] = tree.findall(".//os")
    pestudio_strings["reg"] = tree.findall(".//reg")
    pestudio_strings["guid"] = tree.findall(".//guid")
    pestudio_strings["ssdl"] = tree.findall(".//ssdl")
    pestudio_strings["ext"] = tree.findall(".//ext")
    pestudio_strings["agent"] = tree.findall(".//agent")
    pestudio_strings["oid"] = tree.findall(".//oid")
    pestudio_strings["priv"] = tree.findall(".//priv")

    # Obsolete
    # for elem in string_elems:
    #    strings.append(elem.text)

    return pestudio_strings


def get_pestudio_score(string):
    for type in pestudio_strings:
        for elem in pestudio_strings[type]:
            # Full match
            if elem.text.lower() == string.lower():
                # Exclude the "extension" black list for now
                if type != "ext":
                    return 5, type
    return 0, ""


def get_opcode_string(opcode):
    return ' '.join(opcode[i:i + 2] for i in range(0, len(opcode), 2))


def get_uint_string(magic):
    if len(magic) == 2:
        return "uint16(0) == 0x{1}{0}".format(magic[0].encode('hex'), magic[1].encode('hex'))
    if len(magic) == 4:
        return "uint32(0) == 0x{3}{2}{1}{0}".format(magic[0].encode('hex'), magic[1].encode('hex'),
                                                    magic[2].encode('hex'), magic[3].encode('hex'))
    return ""


def get_file_range(size):
    size_string = ""
    try:
        # max sample size - args.fm times the original size
        max_size_b = size * args.fm
        # Minimum size
        if max_size_b < 1024:
            max_size_b = 1024
        # in KB
        max_size = max_size_b / 1024
        max_size_kb = max_size
        # Round
        if len(str(max_size)) == 2:
            max_size = int(round(max_size, -1))
        elif len(str(max_size)) == 3:
            max_size = int(round(max_size, -2))
        elif len(str(max_size)) == 4:
            max_size = int(round(max_size, -3))
        elif len(str(max_size)) == 5:
            max_size = int(round(max_size, -3))
        size_string = "filesize < {0}KB".format(max_size)
        if args.debug:
            print("File Size Eval: SampleSize (b): {0} SizeWithMultiplier (b/Kb): {1} / {2} RoundedSize: {3}".format(
                str(size), str(max_size_b), str(max_size_kb), str(max_size)))
    except Exception as e:
        if args.debug:
            traceback.print_exc()
        pass
    finally:
        return size_string


def get_timestamp_basic(date_obj=None):
    if not date_obj:
        date_obj = datetime.datetime.now()
    date_str = date_obj.strftime("%Y-%m-%d")
    return date_str


def is_ascii_char(b, padding_allowed=False):
    if padding_allowed:
        if (ord(b) < 127 and ord(b) > 31) or ord(b) == 0:
            return 1
    else:
        if ord(b) < 127 and ord(b) > 31:
            return 1
    return 0


def is_ascii_string(string, padding_allowed=False):
    for b in string:
        if padding_allowed:
            if not ((ord(b) < 127 and ord(b) > 31) or ord(b) == 0):
                return 0
        else:
            if not (ord(b) < 127 and ord(b) > 31):
                return 0
    return 1


def is_base_64(s):
    return (len(s) % 4 == 0) and re.match('^[A-Za-z0-9+/]+[=]{0,2}$', s)


def is_hex_encoded(s, check_length=True):
    if re.match('^[A-Fa-f0-9]+$', s):
        if check_length:
            if len(s) % 2 == 0:
                return True
        else:
            return True
    return False


def extract_hex_strings(s):
    strings = []
    hex_strings = re.findall("([a-fA-F0-9]{10,})", s)
    for string in list(hex_strings):
        hex_strings += string.split('0000')
        hex_strings += string.split('0d0a')
        hex_strings += re.findall(r'((?:0000|002[a-f0-9]|00[3-9a-f][0-9a-f]){6,})', string, re.IGNORECASE)
    hex_strings = list(set(hex_strings))
    # ASCII Encoded Strings
    for string in hex_strings:
        for x in string.split('00'):
            if len(x) > 10:
                strings.append(x)
    # WIDE Encoded Strings
    for string in hex_strings:
        try:
            if len(string) % 2 != 0 or len(string) < 8:
                continue
            dec = string.replace('00', '').decode('hex')
            #print("Testing: %s" % string)
            #print("Decoded: %s" % dec)
            if is_ascii_string(dec, padding_allowed=True):
                #print("CAN USE >>>>>>>>>>>>>>>>>>>>>>>> %s"  % string)
                strings.append(string)
        except Exception as e:
            traceback.print_exc()
    #print len(hex_strings)
    #sys.exit(0)
    return strings


def removeNonAsciiDrop(string):
    nonascii = "error"
    try:
        # Generate a new string without disturbing characters
        nonascii = "".join(i for i in string if ord(i)<127 and ord(i)>31)
    except Exception as e:
        traceback.print_exc()
        pass
    return nonascii


def save(object, filename, protocol=0):
    file = gzip.GzipFile(filename, 'wb')
    file.write(pickle.dumps(object, protocol))
    file.close()


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


def update_databases():
    # Preparations
    try:
        dbDir = './dbs/'
        if not os.path.exists(dbDir):
            os.makedirs(dbDir)
    except Exception as e:
        if args.debug:
            traceback.print_exc()
        print("Error while creating the database directory ./dbs")
        sys.exit(1)

    # Downloading current repository
    try:
        for filename, repo_url in REPO_URLS.iteritems():
            print("Downloading %s from %s ..." % (filename, repo_url))
            fileDownloader = urllib.URLopener()
            fileDownloader.retrieve(repo_url, "./dbs/%s" % filename)
    except Exception as e:
        if args.debug:
            traceback.print_exc()
        print("Error while downloading the database file - check your Internet connection")
        print("Alterntive download link: https://drive.google.com/drive/folders/0B2S_IOa0MiOHS0xmekR6VWRhZ28")
        print("Download the files and place them into the ./dbs/ folder")
        sys.exit(1)


def processSampleDir(targetDir):
    """
    Processes samples in a given directory and creates a yara rule file
    :param directory:
    :return:
    """
    # Special strings
    base64strings = {}
    hexEncStrings = {}
    reversedStrings = {}
    pestudioMarker = {}
    stringScores = {}

    # Extract all information
    (sample_string_stats, sample_opcode_stats, file_info) = \
        parse_sample_dir(targetDir, args.nr, generateInfo=True, onlyRelevantExtensions=args.oe)

    # Evaluate Strings
    (file_strings, file_opcodes, combinations, super_rules, inverse_stats) = \
        sample_string_evaluation(sample_string_stats, sample_opcode_stats, file_info)

    # Create Rule Files
    (rule_count, inverse_rule_count, super_rule_count) = \
        generate_rules(file_strings, file_opcodes, super_rules, file_info, inverse_stats)

    if args.inverse:
        print("[=] Generated %s INVERSE rules." % str(inverse_rule_count))
    else:
        print("[=] Generated %s SIMPLE rules." % str(rule_count))
        if not nosuper:
            print("[=] Generated %s SUPER rules." % str(super_rule_count))
        print("[=] All rules written to %s" % args.o)


def emptyFolder(dir):
    """
    Removes all files from a given folder
    :return:
    """
    for file in os.listdir(dir):
        filePath = os.path.join(dir, file)
        try:
            if os.path.isfile(filePath):
                print("[!] Removing %s ..." % filePath)
                os.unlink(filePath)
        except Exception as e:
            print(e)


def getReference(ref):
    """
    Get a reference string - if the provided string is the path to a text file, then read the contents and return it as
    reference
    :param ref:
    :return:
    """
    if os.path.exists(ref):
        reference = getFileContent(ref)
        print("[+] Read reference from file %s > %s" % (ref, reference))
        return reference
    else:
        return ref


def getIdentifier(id, path):
    """
    Get a identifier string - if the provided string is the path to a text file, then read the contents and return it as
    reference, otherwise use the last element of the full path
    :param ref:
    :return:
    """
    # Identifier
    if id == "not set" or not os.path.exists(id):
        # Identifier is the highest folder name
        return os.path.basename(path.rstrip('/'))
    else:
        # Read identifier from file
        identifier = getFileContent(id)
        print("[+] Read identifier from file %s > %s" % (id, identifier))
        return identifier


def getPrefix(prefix, identifier):
    """
    Get a prefix string for the rule description based on the identifier
    :param prefix:
    :param identifier:
    :return:
    """
    if prefix == "Auto-generated rule":
        return identifier
    else:
        return prefix


def getFileContent(file):
    """
    Gets the contents of a file (limited to 1024 characters)
    :param file:
    :return:
    """
    try:
        with open(file) as f:
            return f.read(1024)
    except Exception as e:
        return "not found"


# CTRL+C Handler --------------------------------------------------------------
def signal_handler(signal_name, frame):
    print("> yarGen's work has been interrupted")
    sys.exit(0)


def print_welcome():
    print("###############################################################################")
    print("                        ______")
    print("      __  ______ ______/ ____/__  ____")
    print("     / / / / __ `/ ___/ / __/ _ \/ __ \\")
    print("    / /_/ / /_/ / /  / /_/ /  __/ / / /")
    print("    \__, /\__,_/_/   \____/\___/_/ /_/")
    print("   /____/")
    print("   ")
    print("   Yara Rule Generator by Florian Roth")
    print("   December 2018")
    print("   Version %s" % __version__)
    print("   ")
    print("###############################################################################")


# MAIN ################################################################
if __name__ == '__main__':

    # Signal handler for CTRL+C
    signal_module.signal(signal_module.SIGINT, signal_handler)

    # Parse Arguments
    parser = argparse.ArgumentParser(description='yarGen')

    group_creation = parser.add_argument_group('Rule Creation')
    group_creation.add_argument('-m', help='Path to scan for malware')
    group_creation.add_argument('-y', help='Minimum string length to consider (default=8)', metavar='min-size',
                                default=8)
    group_creation.add_argument('-z', help='Minimum score to consider (default=0)', metavar='min-score', default=0)
    group_creation.add_argument('-x', help='Score required to set string as \'highly specific string\' (default: 30)',
                                metavar='high-scoring', default=30)
    group_creation.add_argument('-w', help='Minimum number of strings that overlap to create a super rule (default: 5)',
                                metavar='superrule-overlap', default=5)
    group_creation.add_argument('-s', help='Maximum length to consider (default=128)', metavar='max-size', default=128)
    group_creation.add_argument('-rc', help='Maximum number of strings per rule (default=20, intelligent filtering '
                                            'will be applied)', metavar='maxstrings', default=20)
    group_creation.add_argument('--excludegood', help='Force the exclude all goodware strings', action='store_true',
                                default=False)

    group_output = parser.add_argument_group('Rule Output')
    group_output.add_argument('-o', help='Output rule file', metavar='output_rule_file', default='yargen_rules.yar')
    group_output.add_argument('-e', help='Output directory for string exports', metavar='output_dir_strings', default='')
    group_output.add_argument('-a', help='Author Name', metavar='author', default='yarGen Rule Generator')
    group_output.add_argument('-r', help='Reference (can be string or text file)', metavar='ref',
                              default='https://github.com/Neo23x0/yarGen')
    group_output.add_argument('-l', help='License', metavar='lic', default='')
    group_output.add_argument('-p', help='Prefix for the rule description', metavar='prefix',
                              default='Auto-generated rule')
    group_output.add_argument('-b', help='Text file from which the identifier is read (default: last folder name in '
                                         'the full path, e.g. "myRAT" if -m points to /mnt/mal/myRAT)',
                              metavar='identifier',
                              default='not set')
    group_output.add_argument('--score', help='Show the string scores as comments in the rules', action='store_true',
                              default=False)
    group_output.add_argument('--strings', help='Show the string scores as comments in the rules', action='store_true',
                              default=False)
    group_output.add_argument('--nosimple', help='Skip simple rule creation for files included in super rules',
                              action='store_true', default=False)
    group_output.add_argument('--nomagic', help='Don\'t include the magic header condition statement',
                              action='store_true', default=False)
    group_output.add_argument('--nofilesize', help='Don\'t include the filesize condition statement',
                              action='store_true', default=False)
    group_output.add_argument('-fm', help='Multiplier for the maximum \'filesize\' condition value (default: 3)',
                              default=3)
    group_output.add_argument('--globalrule', help='Create global rules (improved rule set speed)',
                              action='store_true', default=False)
    group_output.add_argument('--nosuper', action='store_true', default=False, help='Don\'t try to create super rules '
                                                                                    'that match against various files')

    group_db = parser.add_argument_group('Database Operations')
    group_db.add_argument('--update', action='store_true', default=False, help='Update the local strings and opcodes '
                                                                               'dbs from the online repository')
    group_db.add_argument('-g', help='Path to scan for goodware (dont use the database shipped with yaraGen)')
    group_db.add_argument('-u', action='store_true', default=False, help='Update local standard goodware database with '
                                                                         'a new analysis result (used with -g)')
    group_db.add_argument('-c', action='store_true', default=False, help='Create new local goodware database '
                                                                         '(use with -g and optionally -i "identifier")')
    group_db.add_argument('-i', default="", help='Specify an identifier for the newly created databases '
                                                 '(good-strings-identifier.db, good-opcodes-identifier.db)')

    group_general = parser.add_argument_group('General Options')
    group_general.add_argument('--dropzone', action='store_true', default=False,
                               help='Dropzone mode - monitors a directory [-m] for new samples to process'
                                    'WARNING: Processed files will be deleted!')
    group_general.add_argument('--nr', action='store_true', default=False, help='Do not recursively scan directories')
    group_general.add_argument('--oe', action='store_true', default=False, help='Only scan executable extensions EXE, '
                                                                                'DLL, ASP, JSP, PHP, BIN, INFECTED')
    group_general.add_argument('-fs', help='Max file size in MB to analyze (default=10)', metavar='size-in-MB',
                               default=10)
    group_general.add_argument('--noextras', action='store_true', default=False,
                              help='Don\'t use extras like Imphash or PE header specifics')
    group_general.add_argument('--debug', action='store_true', default=False, help='Debug output')
    group_general.add_argument('--trace', action='store_true', default=False, help='Trace output')

    group_opcode = parser.add_argument_group('Other Features')
    group_opcode.add_argument('--opcodes', action='store_true', default=False, help='Do use the OpCode feature '
                                                                                    '(use this if not enough high '
                                                                                    'scoring strings can be found)')
    group_opcode.add_argument('-n', help='Number of opcodes to add if not enough high scoring string could be found '
                                         '(default=3)', metavar='opcode-num', default=3)

    group_inverse = parser.add_argument_group('Inverse Mode (unstable)')
    group_inverse.add_argument('--inverse', help=argparse.SUPPRESS, action='store_true', default=False)
    group_inverse.add_argument('--nodirname', help=argparse.SUPPRESS, action='store_true', default=False)
    group_inverse.add_argument('--noscorefilter', help=argparse.SUPPRESS, action='store_true', default=False)

    args = parser.parse_args()

    # Print Welcome
    print_welcome()

    if not args.update and not args.m and not args.g:
        parser.print_help()
        print("")
        print("[E] You have to select --update to update yarGens database or -m for signature generation or -g for the "
              "creation of goodware string collections "
              "(see https://github.com/Neo23x0/yarGen#examples for more details)")
        sys.exit(1)

    # Update
    if args.update:
        update_databases()
        print("[+] Updated databases - you can now start creating YARA rules")
        sys.exit(0)

    # Typical input erros
    if args.m:
        if os.path.isfile(args.m):
            print("[E] Input is a file, please use a directory instead (-m path)")
            sys.exit(0)

    # Opcodes evaluation or not
    use_opcodes = False
    if args.opcodes:
        use_opcodes = True

    # Read PEStudio string list
    pestudio_strings = {}
    pestudio_available = False

    # Super Rule Generation
    nosuper = args.nosuper

    # Identifier
    sourcepath = args.m
    if args.g:
        sourcepath = args.g
    identifier = getIdentifier(args.b, sourcepath)
    print("[+] Using identifier '%s'" % identifier)

    # Reference
    reference = getReference(args.r)
    print("[+] Using reference '%s'" % reference)

    # Prefix
    prefix = getPrefix(args.p, identifier)
    print("[+] Using prefix '%s'" % prefix)

    if os.path.isfile(get_abs_path(PE_STRINGS_FILE)) and lxml_available:
        print("[+] Processing PEStudio strings ...")
        pestudio_strings = initialize_pestudio_strings()
        pestudio_available = True
    else:
        if lxml_available:
            print("\nTo improve the analysis process please download the awesome PEStudio tool by marc @ochsenmeier " \
                  "from http://winitor.com and place the file 'strings.xml' in the ./3rdparty directory.\n")
            time.sleep(5)

    # Highly specific string score
    score_highly_specific = int(args.x)

    # Scan goodware files
    if args.g:
        print("[+] Processing goodware files ...")
        good_strings_db, good_opcodes_db, good_imphashes_db, good_exports_db = \
            parse_good_dir(args.g, args.nr, args.oe)

        # Update existing databases
        if args.u:
            try:
                print("[+] Updating databases ...")

                # Evaluate the database identifiers
                db_identifier = ""
                if args.i != "":
                    db_identifier = "-%s" % args.i
                strings_db = "./dbs/good-strings%s.db" % db_identifier
                opcodes_db = "./dbs/good-opcodes%s.db" % db_identifier
                imphashes_db = "./dbs/good-imphashes%s.db" % db_identifier
                exports_db = "./dbs/good-exports%s.db" % db_identifier

                # Strings -----------------------------------------------------
                print("[+] Updating %s ..." % strings_db)
                good_pickle = load(get_abs_path(strings_db))
                print("Old string database entries: %s" % len(good_pickle))
                good_pickle.update(good_strings_db)
                print("New string database entries: %s" % len(good_pickle))
                save(good_pickle, strings_db)

                # Opcodes -----------------------------------------------------
                print("[+] Updating %s ..." % opcodes_db)
                good_opcode_pickle = load(get_abs_path(opcodes_db))
                print("Old opcode database entries: %s" % len(good_opcode_pickle))
                good_opcode_pickle.update(good_opcodes_db)
                print("New opcode database entries: %s" % len(good_opcode_pickle))
                save(good_opcode_pickle, opcodes_db)

                # Imphashes ---------------------------------------------------
                print("[+] Updating %s ..." % imphashes_db)
                good_imphashes_pickle = load(get_abs_path(imphashes_db))
                print("Old opcode database entries: %s" % len(good_imphashes_pickle))
                good_imphashes_pickle.update(good_imphashes_db)
                print("New opcode database entries: %s" % len(good_imphashes_pickle))
                save(good_imphashes_pickle, imphashes_db)

                # Exports -----------------------------------------------------
                print("[+] Updating %s ..." % exports_db)
                good_exports_pickle = load(get_abs_path(exports_db))
                print("Old opcode database entries: %s" % len(good_exports_pickle))
                good_exports_pickle.update(good_exports_db)
                print("New opcode database entries: %s" % len(good_exports_pickle))
                save(good_exports_pickle, exports_db)

            except Exception as e:
                traceback.print_exc()

        # Create new databases
        if args.c:
            print("[+] Creating local database ...")
            # Evaluate the database identifiers
            db_identifier = ""
            if args.i != "":
                db_identifier = "-%s" % args.i
            strings_db = "./dbs/good-strings%s.db" % db_identifier
            opcodes_db = "./dbs/good-opcodes%s.db" % db_identifier
            imphashes_db = "./dbs/good-imphashes%s.db" % db_identifier
            exports_db = "./dbs/good-exports%s.db" % db_identifier

            # Creating the databases
            print("[+] Using '%s' as filename for newly created strings database" % strings_db)
            print("[+] Using '%s' as filename for newly created opcodes database" % opcodes_db)
            print("[+] Using '%s' as filename for newly created opcodes database" % imphashes_db)
            print("[+] Using '%s' as filename for newly created opcodes database" % exports_db)

            try:

                if os.path.isfile(strings_db):
                    input("File %s alread exists. Press enter to proceed or CTRL+C to exit." % strings_db)
                    os.remove(strings_db)
                if os.path.isfile(opcodes_db):
                    input("File %s alread exists. Press enter to proceed or CTRL+C to exit." % opcodes_db)
                    os.remove(opcodes_db)
                if os.path.isfile(imphashes_db):
                    input("File %s alread exists. Press enter to proceed or CTRL+C to exit." % imphashes_db)
                    os.remove(imphashes_db)
                if os.path.isfile(exports_db):
                    input("File %s alread exists. Press enter to proceed or CTRL+C to exit." % exports_db)
                    os.remove(exports_db)

                # Strings
                good_pickle = Counter()
                good_pickle = good_strings_db
                # Opcodes
                good_op_pickle = Counter()
                good_op_pickle = good_opcodes_db
                # Imphashes
                good_imphashes_pickle = Counter()
                good_imphashes_pickle = good_imphashes_db
                # Exports
                good_exports_pickle = Counter()
                good_exports_pickle = good_exports_db

                # Save
                save(good_pickle, strings_db)
                save(good_op_pickle, opcodes_db)
                save(good_imphashes_pickle, imphashes_db)
                save(good_exports_pickle, exports_db)

                print("New database with %d string, %d opcode, %d imphash, %d export entries created. " \
                      "(remember to use --opcodes to extract opcodes from the samples and create the opcode databases)"\
                      % (len(good_strings_db), len(good_opcodes_db), len(good_imphashes_db), len(good_exports_db)))
            except Exception as e:
                traceback.print_exc()

    # Analyse malware samples and create rules
    else:
        if use_opcodes:
            print("[+] Reading goodware strings from database 'good-strings.db' and 'good-opcodes.db' ...")
            print("    (This could take some time and uses at least 6 GB of RAM)")
        else:
            print("[+] Reading goodware strings from database 'good-strings.db' ...")
            print("    (This could take some time and uses at least 3 GB of RAM)")

        good_strings_db = Counter()
        good_opcodes_db = Counter()
        good_imphashes_db = Counter()
        good_exports_db = Counter()

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
            if file.startswith("good-strings"):
                try:
                    print("[+] Loading %s ..." % filePath)
                    good_pickle = load(get_abs_path(filePath))
                    good_strings_db.update(good_pickle)
                    print("[+] Total: %s / Added %d entries" % (
                    len(good_strings_db), len(good_strings_db) - strings_num))
                    strings_num = len(good_strings_db)
                except Exception as e:
                    traceback.print_exc()
            # Opcode databases
            if file.startswith("good-opcodes"):
                try:
                    if use_opcodes:
                        print("[+] Loading %s ..." % filePath)
                        good_op_pickle = load(get_abs_path(filePath))
                        good_opcodes_db.update(good_op_pickle)
                        print("[+] Total: %s (removed duplicates) / Added %d entries" % (
                        len(good_opcodes_db), len(good_opcodes_db) - opcodes_num))
                        opcodes_num = len(good_opcodes_db)
                except Exception as e:
                    use_opcodes = False
                    traceback.print_exc()
            # Imphash databases
            if file.startswith("good-imphash"):
                try:
                    print("[+] Loading %s ..." % filePath)
                    good_imphashes_pickle = load(get_abs_path(filePath))
                    good_imphashes_db.update(good_imphashes_pickle)
                    print("[+] Total: %s / Added %d entries" % (
                    len(good_imphashes_db), len(good_imphashes_db) - imphash_num))
                    imphash_num = len(good_imphashes_db)
                except Exception as e:
                    traceback.print_exc()
            # Export databases
            if file.startswith("good-exports"):
                try:
                    print("[+] Loading %s ..." % filePath)
                    good_exports_pickle = load(get_abs_path(filePath))
                    good_exports_db.update(good_exports_pickle)
                    print("[+] Total: %s / Added %d entries" % (
                    len(good_exports_db), len(good_exports_db) - exports_num))
                    exports_num = len(good_exports_db)
                except Exception as e:
                    traceback.print_exc()

        if use_opcodes and len(good_opcodes_db) < 1:
            print("[E] Missing goodware opcode databases."
                  "    Please run 'yarGen.py --update' to retrieve the newest database set.")
            use_opcodes = False

        if len(good_exports_db) < 1 and len(good_imphashes_db) < 1:
            print("[E] Missing goodware imphash/export databases. "
                  "    Please run 'yarGen.py --update' to retrieve the newest database set.")
            use_opcodes = False

        if len(good_strings_db) < 1 and not args.c:
            print("[E] Error - no goodware databases found. "
                  "    Please run 'yarGen.py --update' to retrieve the newest database set.")
            sys.exit(1)

    # If malware directory given
    if args.m:

        # Initialize Bayes Trainer (we will use the goodware string database for this)
        print("[+] Initializing Bayes Filter ...")
        stringTrainer = initialize_bayes_filter()

        # Deactivate super rule generation if there's only a single file in the folder
        if len(os.listdir(args.m)) < 2:
            nosuper = True

        # Special strings
        base64strings = {}
        reversedStrings = {}
        hexEncStrings = {}
        pestudioMarker = {}
        stringScores = {}

        # Dropzone mode
        if args.dropzone:
            # Monitoring folder for changes
            print("Monitoring %s for new sample files (processed samples will be removed)" % args.m)
            while(True):
                if len(os.listdir(args.m)) > 0:
                    # Deactivate super rule generation if there's only a single file in the folder
                    if len(os.listdir(args.m)) < 2:
                        nosuper = True
                    else:
                        nosuper = False
                    # Read a new identifier
                    identifier = getIdentifier(args.b, args.m)
                    # Read a new reference
                    reference = getReference(args.r)
                    # Generate a new description prefix
                    prefix = getPrefix(args.p, identifier)
                    # Process the samples
                    processSampleDir(args.m)
                    # Delete all samples from the dropzone folder
                    emptyFolder(args.m)
                time.sleep(1)
        else:
            # Scan malware files
            print("[+] Processing malware files ...")
            processSampleDir(args.m)

        print("[+] yarGen run finished")