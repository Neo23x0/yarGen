#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# yarGen
# A rule generator for Yara rules
#
# Florian Roth

import os
import sys
import argparse
import re
import traceback
import pickle
import gzip
import operator
import datetime
import time
import scandir
from hashlib import sha1
from collections import OrderedDict
try:
    from lxml import etree
    lxml_available = True
except Exception, e:
    print "lxml not found - disabling PeStudio string check functionality"
    lxml_available = False
from lib import gibDetector

RELEVANT_EXTENSIONS = [ ".asp", ".vbs", ".ps", ".ps1", ".rar", ".tmp", ".bas", ".bat", ".chm", ".cmd", ".com", ".cpl",
                         ".crt", ".dll", ".exe", ".hta", ".js", ".lnk", ".msc", ".ocx", ".pcd", ".pif", ".pot", ".reg",
                         ".scr", ".sct", ".sys", ".vb", ".vbe", ".vbs", ".wsc", ".wsf", ".wsh", ".ct", ".t", ".input",
                         ".war", ".jsp", ".php", ".asp", ".aspx", ".psd1", ".psm1" ]

def getFiles(dir, notRecursive):
    # Not Recursive
    if notRecursive:
        for filename in os.listdir(dir):
            filePath = os.path.join(dir,filename)
            yield filePath
    # Recursive
    else:
        for root, directories, files in scandir.walk (dir, followlinks=False):
            for filename in files:
                filePath = os.path.join(root,filename)
                yield filePath


def parseMalDir(dir, notRecursive=False, generateInfo=False, onlyRelevantExtensions=False):

    # Prepare dictionary
    string_stats = {}
    file_info = {}
    known_sha1sums = []

    for filePath in getFiles(dir, notRecursive):

        # Get Extension
        extension = os.path.splitext(filePath)[1].lower()
        if not extension in RELEVANT_EXTENSIONS and onlyRelevantExtensions:
            if args.debug:
                print "EXTENSION %s - Skipping file %s" % ( extension, filePath )
            continue

        # Size Check
        size = 0
        try:
            size = os.stat(filePath).st_size
            if size > ( args.fs * 1024 * 1024 ):
                if args.debug:
                    print "File is to big - Skipping file %s (use -fs to adjust this behaviour)" % ( filePath )
                continue
        except Exception, e:
            pass

        # Extract strings from file
        ( strings, sha1sum ) = extractStrings(filePath, generateInfo)

        # Skip if MD5 already known - avoid duplicate files
        if sha1sum in known_sha1sums:
            #if args.debug:
            print "Skipping strings from %s due to MD5 duplicate detection" % filePath
            continue

        # Add md5 value
        if generateInfo:
            known_sha1sums.append(sha1sum)
            file_info[filePath] = {}
            file_info[filePath]["md5"] = sha1sum

        # Magic evaluation
        if not args.nomagic:
            file_info[filePath]["magic"] = getMagic(filePath)
        else:
            file_info[filePath]["magic"] = ""

        # File Size
        file_info[filePath]["size"] = os.stat(filePath).st_size

        # Add strings to statistics
        invalid_count = 0
        for string in strings:
            if string in string_stats:
                string_stats[string]["count"] += 1
                string_stats[string]["files"].append(filePath)
            else:
                string_stats[string] = {}
                string_stats[string]["count"] = 0
                string_stats[string]["files"] = []
                string_stats[string]["files"].append(filePath)

        if args.debug:
            print "Processed " + filePath + " Size: "+ str(size) +" Strings: "+ str(len(string_stats)) + " ... "

    return string_stats, file_info


def parseGoodDir(dir, notRecursive=False, onlyRelevantExtensions=True):

    # Prepare dictionary
    all_strings = []

    for filePath in getFiles(dir, notRecursive):
        # Get Extension
        extension = os.path.splitext(filePath)[1].lower()
        if not extension in RELEVANT_EXTENSIONS and onlyRelevantExtensions:
            if args.debug:
                print "EXTENSION %s - Skipping file %s" % ( extension, filePath )
            continue

        # Size Check
        size = 0
        try:
            size = os.stat(filePath).st_size
            if size > 3000000:
                continue
        except Exception, e:
            pass

        # Extract strings from file
        ( strings, sha1sum ) = extractStrings(filePath, generateInfo=False)
        # Append to all strings
        all_strings += strings

    # return it as a set (unique strings)
    return set(all_strings)


def extractStrings(filePath, generateInfo):
    # String list
    strings = []
    cleaned_strings	= []
    sha1sum = ""
    # Read file data
    try:
        f = open(filePath, 'rb')
        print "Processing: %s" % filePath
        data = f.read()
        f.close()
        # Generate md5
        if generateInfo:
            sha1sum = sha1(data).hexdigest()

        # Read strings
        strings = re.findall("[\x1f-\x7e]{6,}", data)
        if args.debug:
            print "%s ASCII strings extracted" % len(strings)
            ascii_count = len(strings)
        strings += [str("UTF16LE:%s" % ws.decode("utf-16le")) for ws in re.findall("(?:[\x1f-\x7e][\x00]){6,}", data)]
        if args.debug:
            print "%s ASCII strings extracted" % ( len(strings) - ascii_count )

        # Escape strings
        for string in strings:
            # Check if last bytes have been string and not yet saved to list
            if len(string) > 0:
                string = string.replace('\\','\\\\')
                string = string.replace('"','\\"')
                if not string in cleaned_strings:
                    cleaned_strings.append(string.lstrip(" "))

    except Exception,e:
        if args.debug:
            traceback.print_exc()
        pass

    return cleaned_strings, sha1sum


def malwareStringEvaluation(mal_string_stats, good_strings):

    # Generate Stats --------------------------------------------------
    print "Generating statistical data ..."
    file_strings = {}
    combinations = {}
    max_combi_count = 0

    # Iterate through strings found in malware files
    for string in mal_string_stats:

        # Skip if string is a good string
        if string in good_strings:
            continue

        # If string occurs not too often in malware files
        if mal_string_stats[string]["count"] < 10:
            if args.debug:
                # print "String: " +string +" Found in: "+ ", ".join(mal_string_stats[string]["files"])
                pass
            # If string list in file dictionary not yet exists
            for file in mal_string_stats[string]["files"]:
                if file in file_strings:
                    # Append string
                    file_strings[file].append(string)
                else:
                    # Create list and than add the first string to the file
                    file_strings[file] = []
                    file_strings[file].append(string)

        # SUPER RULES GENERATOR	- preliminary work
        # If a string occurs more than once in different files
        if mal_string_stats[string]["count"] > 1:
            if args.debug:
                print "OVERLAP Count: %s\nString: \"%s\"%s" % ( mal_string_stats[string]["count"], string, "\nFILE: ".join(mal_string_stats[string]["files"]) )
            # Create a combination string from the file set that matches to that string
            combi = ":".join(sorted(mal_string_stats[string]["files"]))
            # print "STRING: " + string
            # print "COMBI: " + combi
            # If combination not yet known
            if not combi in combinations:
                combinations[combi] = {}
                combinations[combi]["count"] = 1
                combinations[combi]["strings"] = []
                combinations[combi]["strings"].append(string)
                combinations[combi]["files"] = mal_string_stats[string]["files"]
            else:
                combinations[combi]["count"] += 1
                combinations[combi]["strings"].append(string)
            # Set the maximum combination count
            if combinations[combi]["count"] > max_combi_count:
                max_combi_count = combinations[combi]["count"]
                # print "Max Combi Count set to: %s" % max_combi_count

    # SUPER RULE GENERATION -------------------------------------------
    super_rules = []
    if not args.nosuper:
        print "Generating Super Rules ... (a lot of foo magic)"
        for combi_count in range(max_combi_count, 1, -1):
            for combi in combinations:
                if combi_count == combinations[combi]["count"]:
                    #print "Count %s - Combi %s" % ( str(combinations[combi]["count"]), combi )
                    # Filter the string set
                    #print "BEFORE"
                    #print len(combinations[combi]["strings"])
                    string_set = combinations[combi]["strings"]
                    combinations[combi]["strings"] = []
                    combinations[combi]["strings"] = filterStringSet(string_set)
                    #print "AFTER"
                    #print len(combinations[combi]["strings"])
                    # Combi String count after filtering
                    #print "String count after filtering: %s" % str(len(combinations[combi]["strings"]))
                    # If the string set of the combination has a required size
                    if len(combinations[combi]["strings"]) >= int(args.rc):
                        # Remove the files in the combi rule from the simple set
                        for file in combinations[combi]["files"]:
                            if file in file_strings:
                                del file_strings[file]
                        # Add it as a super rule
                        print "Adding Super Rule with %s strings." % str(len(combinations[combi]["strings"]))
                        super_rules.append(combinations[combi])

    return (file_strings, combinations, super_rules)


def filterStringSet(string_set):

    # This is the only set we have - even if it's a weak one
    useful_set = []

    # Gibberish Detector
    gib = gibDetector.GibDetector()

    # String scores
    stringScores = {}
    utfstrings = []

    for string in string_set:

        # UTF
        if string[:8] == "UTF16LE:":
            string = string[8:]
            utfstrings.append(string)

        # Gibberish Score
        score = gib.getScore(string)
        # score = 1
        if score > 10:
            score = 1
        if args.debug:
            print "%s - %s" % ( str(score), string)
        stringScores[string] = score

        # Length Score
        length = len(string)
        if length > int(args.l) and length < int(args.s):
            stringScores[string] += round( len(string) / 8, 2)
        if length >= int(args.s):
            stringScores[string] += 1

        # In suspicious strings
        if string in suspicious_strings:
            stringScores[string] += 6

        # Reduction
        if ".." in string:
            stringScores[string] -= 5
        if "   " in string:
            stringScores[string] -= 5

        # Certain strings add-ons ----------------------------------------------
        # Extensions - Drive
        if re.search(r'([A-Za-z]:\\|\.exe|\.pdb|\.scr|\.log|\.cfg|\.txt|\.dat|\.msi|\.com|\.bat|\.dll|\.pdb|\.[a-z][a-z][a-z])', string, re.IGNORECASE):
            stringScores[string] += 4
        # System keywords
        if re.search(r'(cmd.exe|system32|users|Documents and|SystemRoot|Grant|hello|password|process|log|unc)', string, re.IGNORECASE):
            stringScores[string] += 5
        # Protocol Keywords
        if re.search(r'(ftp|irc|smtp|command|GET|POST|Agent|tor2web|HEAD)', string, re.IGNORECASE):
            stringScores[string] += 5
        # Connection keywords
        if re.search(r'(error|http|closed|fail|version)', string, re.IGNORECASE):
            stringScores[string] += 3
        # Browser User Agents
        if re.search(r'(Mozilla|MSIE|Windows NT|Macintosh|Gecko|Opera|User\-Agent)', string, re.IGNORECASE):
            stringScores[string] += 5
        # Temp and Recycler
        if re.search(r'(TEMP|Temporary|Appdata|Recycler)', string, re.IGNORECASE):
            stringScores[string] += 4
        # malicious keywords - hacktools
        if re.search(r'(scan|sniff|poison|fake|spoof|sweep|dump|flood|inject|forward|scan|vulnerable|credentials|creds|coded|p0c|Content|host)', string, re.IGNORECASE):
            stringScores[string] += 5
        # network keywords
        if re.search(r'(address|port|listen|remote|local|process|service|mutex|pipe|frame|key|lookup|connection)', string, re.IGNORECASE):
            stringScores[string] += 3
        # Drive non-C:
        if re.search(r'([D-Z]:\\)', string, re.IGNORECASE):
            stringScores[string] += 4
        # IP
        if re.search(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', string, re.IGNORECASE): # IP Address
            stringScores[string] += 5
        # Copyright Owner
        if re.search(r'( by | coded | c0d3d |cr3w\b)', string, re.IGNORECASE):
            stringScores[string] += 2
        # Extension generic
        if re.search(r'\.[a-zA-Z]{3}\b', string):
            stringScores[string] += 3
        # All upper case
        if re.search(r'^[A-Z]{6,}$', string):
            stringScores[string] += 2
        # All lower case
        if re.search(r'^[a-z]{6,}$', string):
            stringScores[string] += 2
        # All lower with space
        if re.search(r'^[a-z\s]{6,}$', string):
            stringScores[string] += 2
        # All characters
        if re.search(r'^[A-Z][a-z]{5,}', string):
            stringScores[string] += 2
        # URL
        if re.search(r'(%[a-z][:\-,;]|\\\\%s|\\\\[A-Z0-9a-z%]+\\[A-Z0-9a-z%]+)', string):
            stringScores[string] += 3
        # certificates
        if re.search(r'(thawte|trustcenter|signing|class|crl|CA|certificate|assembly)', string, re.IGNORECASE):
            stringScores[string] -= 4
        # Parameters
        if re.search(r'( \-[a-z]{,2}[\s]?[0-9]?| /[a-z]+[\s]?[\w]*)', string, re.IGNORECASE):
            stringScores[string] += 4
        # Directory
        if re.search(r'(\\[A-Za-z]+\\)', string):
            stringScores[string] += 4
        # Executable - not in directory
        if re.search(r'^[^\\]+\.(exe|com|scr|bat)$', string, re.IGNORECASE):
            stringScores[string] += 4
        # Date placeholders
        if re.search(r'(yyyy|hh:mm|dd/mm|mm/dd|%s:%s:)', string, re.IGNORECASE):
            stringScores[string] += 3
        # Placeholders
        if re.search(r'(%s|%d|%i|%02d|%04d|%2d|%3s)', string, re.IGNORECASE):
            stringScores[string] += 3
        # String parts from file system elements
        if re.search(r'(cmd|com|pipe|tmp|temp|recycle|bin|secret|private|AppData|driver|config)', string, re.IGNORECASE):
            stringScores[string] += 3
        # Programming
        if re.search(r'(execute|run|system|shell|root|cimv2|login|exec|stdin|read|process|netuse|script|share)', string, re.IGNORECASE):
            stringScores[string] += 3
        # Credentials
        if re.search(r'(user|pass|login|logon|token|cookie|creds|hash|ticket|NTLM|LMHASH|kerberos|spnego|session|identif|account|login|auth|privilege)', string, re.IGNORECASE):
            stringScores[string] += 3

        # Certain string reduce	-----------------------------------------------
        if re.search(r'(rundll32\.exe$|kernel\.dll$)', string, re.IGNORECASE):
            stringScores[string] -= 4

    sorted_set = sorted(stringScores.iteritems(), key=operator.itemgetter(1), reverse=True)

    if args.debug:
        print "SORTED SET:"
        print sorted_set

    # Only the top X strings
    c = 0
    result_set = []
    for string in sorted_set:
        if string[0] in utfstrings:
            result_set.append("UTF16LE:%s" % string[0])
        else:
            result_set.append(string[0])
        c += 1
        if c > int(args.rc):
            break

    if args.debug:
        print "RESULT SET:"
        print result_set

    # return the filtered set
    return result_set


def generateGeneralCondition(file_info):

    condition = ""

    # Different Magic Headers and File Sizes
    magic_headers = []
    file_sizes = []

    for filePath in file_info:
        magic = file_info_mal[filePath]["magic"]
        size = file_info_mal[filePath]["size"]
        if not magic in magic_headers and magic != "":
            magic_headers.append(magic)
        if not size in file_sizes:
            file_sizes.append(size)

    # If different magic headers are less than 5
    if len(magic_headers) <= 5:
        magic_string = " or ".join(getUintString(h) for h in magic_headers)
        if " or " in magic_string:
            condition = "( {0} )".format(magic_string)
        else:
            condition = "{0}".format(magic_string)

    # Biggest size multiplied with maxsize_multiplier
    if not args.nofilesize:
        if condition != "":
            condition = "{0} and {1}".format(condition, getFileRange(max(file_sizes)))
        else:
            condition = "{0}".format(getFileRange(max(file_sizes)))

    return condition


def createRules(file_strings, super_rules, file_info_mal):

    # Write to file ---------------------------------------------------
    if args.o:
        try:
            fh = open(args.o, 'w')
        except Exception, e:
            traceback.print_exc()

    # General Info
    general_info = "/*\n"
    general_info += "\tYara Rule Set\n"
    general_info += "\tAuthor: {0}\n".format(args.a)
    general_info += "\tDate: {0}\n".format(getTimestampBasic())
    general_info += "\tIdentifier: {0}\n".format(os.path.basename(args.m))
    general_info += "*/\n\n"

    fh.write(general_info)

    # GLOBAL RULES ----------------------------------------------------
    if not args.noglobal:

        condition = generateGeneralCondition(file_info_mal)

        # Global Rule
        if condition != "":
            global_rule = "/* Global Rule -------------------------------------------------------------- */\n"
            global_rule += "/* Will be evaluated first, speeds up scanning process, remove at will */\n\n"
            global_rule += "global private rule gen_characteristics {\n"
            global_rule += "\tcondition:\n"
            global_rule += "\t\t{0}\n".format(condition)
            global_rule += "}\n\n"

            # Write rule
            if args.o:
                fh.write(global_rule)

    # PROCESS SIMPLE RULES
    # Apply intelligent filters ---------------------------------------
    print "Applying intelligent filters to string findings ..."
    for filePath in file_strings:

        # Replace the original string set with the filtered one
        string_set = file_strings[filePath]
        file_strings[filePath] = []
        file_strings[filePath] = filterStringSet(string_set)

    # GENERATE SIMPLE RULES -------------------------------------------
    print "Generating simple rules ..."
    fh.write("/* Rule Set ----------------------------------------------------------------- */\n\n")
    rules = ""
    printed_rules = {}
    rule_count = 0
    for filePath in file_strings:
        try:
            rule = ""
            (path, file) = os.path.split(filePath)
            # Prepare name
            fileBase = os.path.splitext(file)[0]
            # Create a clean new name
            cleanedName = fileBase
            # Adapt length of rule name
            if len(fileBase) < 8: # if name is too short add part from path
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
            rule += "\tmeta:\n"
            rule += "\t\tdescription = \"%s - file %s\"\n" % ( args.p, file )
            rule += "\t\tauthor = \"%s\"\n" % args.a
            rule += "\t\treference = \"%s\"\n" % args.r
            rule += "\t\tdate = \"%s\"\n" % getTimestampBasic()
            rule += "\t\thash = \"%s\"\n" % file_info_mal[filePath]["md5"]
            rule += "\tstrings:\n"

            # Adding the strings --------------------------------------
            for i, string in enumerate(file_strings[filePath]):
                # Checking string length
                fullword = True
                if len(string) > 80:
                    # cut string
                    string = string[:80].rstrip("\\")
                    # not fullword anymore
                    fullword = False
                # Add rule
                enc = " ascii"
                if string[:8] == "UTF16LE:":
                    string = string[8:]
                    enc = " wide"
                if fullword:
                    rule += "\t\t$s%s = \"%s\" fullword%s\n" % ( str(i), string, enc )
                else:
                    rule += "\t\t$s%s = \"%s\"%s\n" % ( str(i), string, enc )
                # If too many string definitions found - cut it at the
                # count defined via command line param -rc
                if i > int(args.rc):
                    break

            # Condition -----------------------------------------------
            condition = "all of them"

            # Filesize
            if not args.nofilesize:
                condition = "{0} and {1}".format(getFileRange(file_info_mal[filePath]["size"]), condition)

            # Magic
            if file_info_mal[filePath]["magic"] != "":
                uint_string = getUintString(file_info_mal[filePath]["magic"])
                condition = "{0} and {1}".format(uint_string, condition)

            rule += "\tcondition:\n"
            rule += "\t\t%s\n" % condition
            rule += "}\n\n"

            # print rule
            # Add to rules string
            rules += rule
            # Try to write rule to file
            if args.o:
                fh.write(rule)
            rule_count += 1
        except Exception, e:
            traceback.print_exc()

    # GENERATE SUPER RULES --------------------------------------------
    if not args.nosuper:
        print "Generating super rules ..."
        printed_combi = {}
        super_rule_count = 0
        for super_rule in super_rules:
            try:
                rule = ""
                # Prepare Name
                rule_name = ""
                file_list = []
                # Loop through files
                for filePath in super_rule["files"]:
                    (path, file) = os.path.split(filePath)
                    file_list.append(file)
                    # Prepare name
                    fileBase = os.path.splitext(file)[0]
                    # Create a clean new name
                    cleanedName = fileBase
                    # Append it to the full name
                    rule_name += "_" + cleanedName

                # Shorten rule name
                rule_name = rule_name[:127]

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
                rule += "\tmeta:\n"
                rule += "\t\tdescription = \"%s - from files %s\"\n" % ( args.p, file_listing )
                rule += "\t\tauthor = \"%s\"\n" % args.a
                rule += "\t\treference = \"%s\"\n" % args.r
                rule += "\t\tdate = \"%s\"\n" % getTimestampBasic()
                rule += "\t\tsuper_rule = 1\n"
                for i, filePath in enumerate(super_rule["files"]):
                    rule += "\t\thash%s = \"%s\"\n" % (str(i), file_info_mal[filePath]["md5"])
                rule += "\tstrings:\n"
                # Adding the strings
                for i, string in enumerate(super_rule["strings"]):
                    # Checking string length
                    fullword = True
                    if len(string) > 80:
                        # cut string
                        string = string[:80].rstrip("\\")
                        # not fullword anymore
                        fullword = False
                    # Add rule
                    wide = ""
                    if string[:8] == "UTF16LE:":
                        string = string[8:]
                        wide = " wide"
                    if fullword:
                        rule += "\t\t$s%s = \"%s\" fullword%s\n" % ( str(i), string, wide )
                    else:
                        rule += "\t\t$s%s = \"%s\"%s\n" % ( str(i), string, wide )
                    # If too many string definitions found - cut it at the
                    # count defined via command line param -rc
                    if i > int(args.rc):
                        break

                # Condition -------------------------------------------
                # Default
                condition = "all of them"
                # Evaluate the general characteristics
                file_info_super = {}
                for filePath in super_rule["files"]:
                    file_info_super[filePath] = file_info_mal[filePath]
                condition_extra = generateGeneralCondition(file_info_super)
                if condition_extra != "":
                    condition = "{0} and {1}".format(condition_extra, condition)

                rule += "\tcondition:\n"
                rule += "\t\t{0}\n".format(condition)
                rule += "}\n"

                # print rule
                # Add to rules string
                rules += rule
                # Try to write rule to file
                if args.o:
                    fh.write(rule)
                super_rule_count += 1
            except Exception, e:
                traceback.print_exc()

    # Close the rules file --------------------------------------------
    if args.o:
        try:
            fh.close()
        except Exception, e:
            traceback.print_exc()

    # Print rules to command line -------------------------------------
    if args.debug:
        print rules

    return ( rule_count, super_rule_count )


def readPEStudioStrings():
    tree = etree.parse('PeStudioBlackListStrings.xml')
    string_elems = tree.findall(".//String")
    strings = []
    for elem in string_elems:
        strings.append(elem.text)
    return strings


def getMagic(filePath):
    magic = ""
    try:
        with open(filePath, 'rb') as f:
            magic = f.read(2)
    except Exception, e:
        pass
    finally:
        return magic


def getUintString(magic):
    if len(magic) == 2:
        return "uint16(0) == 0x{1}{0}".format(magic[0].encode('hex'), magic[1].encode('hex'))
    if len(magic) == 4:
        return "uint32(0) == 0x{3}{2}{1}{0}".format(magic[0].encode('hex'), magic[1].encode('hex'), magic[2].encode('hex'), magic[3].encode('hex'))
    return ""


def getFileRange(size):
    size_string = ""
    try:
        # max sample size - args.fm times the original size
        max_size = size * args.fm
        size_string = "filesize < {0}KB".format( max_size / 1024 )
    except Exception, e:
        pass
    finally:
        return size_string


def getTimestampBasic(date_obj=None):
    if not date_obj:
        date_obj = datetime.datetime.now()
    date_str = date_obj.strftime("%Y-%m-%d")
    return date_str


def isAscii(b):
    if ord(b)<127 and ord(b)>31 :
        return 1
    return 0


def save(object, filename, bin = 1):
    file = gzip.GzipFile(filename, 'wb')
    file.write(pickle.dumps(object, bin))
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
    del(buffer)
    file.close()
    return object


def printWelcome():
    print "###############################################################################"
    print "  "
    print "  yarGen"
    print "  Yara Rule Generator"
    print "  "
    print "  by Florian Roth"
    print "  May 2015"
    print "  Version 0.11.1"
    print " "
    print "###############################################################################"


# MAIN ################################################################
if __name__ == '__main__':

    # Parse Arguments
    parser = argparse.ArgumentParser(description='yarGen')
    parser.add_argument('-m', help='Path to scan for malware')
    parser.add_argument('-g', help='Path to scan for goodware (dont use the database shipped with yara-brg)')
    parser.add_argument('-u', action='store_true', default=False, help='Update local goodware database (use with -g)')
    parser.add_argument('-c', action='store_true', default=False, help='Create new local goodware database (use with -g)')
    parser.add_argument('-o', help='Output rule file', metavar='output_rule_file', default='yargen_rules.yar')
    parser.add_argument('-p', help='Prefix for the rule description', metavar='prefix', default='Auto-generated rule')
    parser.add_argument('-a', help='Athor Name', metavar='author', default='YarGen Rule Generator')
    parser.add_argument('-r', help='Reference', metavar='ref', default='not set')
    parser.add_argument('-l', help='Minimum string length to consider (default=6)', metavar='min-size', default=5)
    parser.add_argument('-s', help='Maximum length to consider (default=64)', metavar='max-size', default=64)
    parser.add_argument('-nr', action='store_true', default=False, help='Do not recursively scan directories')
    # parser.add_argument('-rm', action='store_true', default=False, help='Recursive scan of malware directories')
    # parser.add_argument('-rg', action='store_true', default=False, help='Recursive scan of goodware directories')
    parser.add_argument('-oe', action='store_true', default=False, help='Only scan executable extensions EXE, DLL, ASP, JSP, PHP, BIN, INFECTED')
    parser.add_argument('-fs', help='Max file size in MB to analyze (default=3)', metavar='size-in-MB', default=3)
    parser.add_argument('--nomagic', help='Don\'t include the magic header condition statement', action='store_true', default=False)
    parser.add_argument('--nofilesize', help='Don\'t include the filesize condition statement', action='store_true', default=False)
    parser.add_argument('-fm', help='Multiplier for the maximum \'filesize\' condition (default: 5)', default=5)
    parser.add_argument('--noglobal', help='Don\'t create global rules', action='store_true', default=False)
    parser.add_argument('-rc', help='Maximum number of strings per rule (default=20, intelligent filtering will be applied)', metavar='maxstrings', default=20)
    parser.add_argument('--nosuper', action='store_true', default=False, help='Don\'t try to create super rules that match against various files')
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

    args = parser.parse_args()

    # Print Welcome
    printWelcome()

    # Read PEStudio string list
    suspicious_strings = []
    if os.path.exists("PeStudioBlackListStrings.xml") and lxml_available:
        suspicious_strings = readPEStudioStrings()
    else:
        if lxml_available:
            print "To improve the analysis process please download PEStudio from http://winitor.com and place the file 'PeStudioBlackListStrings.xml' in the yarGen program directory."
            time.sleep(5)

    # Ignore File Type on Malware Scan
    onlyRelevantExtensions = False
    if args.oe:
        onlyRelevantExtensions = True

    # Scan goodware files
    if args.g:
        print "Processing goodware files ..."
        good_strings = parseGoodDir(args.g, args.nr, True)

        # Update existing Pickle
        if args.u:
            print "Updating local database ..."
            try:
                good_pickle = load("good_strings.db")
                print "Old database entries: %s" % len(good_pickle)
                new_good = set()
                new_good = good_strings | good_pickle
                good_pickle = new_good
                print "New database entries: %s" % len(good_pickle)
                save(good_pickle, "good_strings.db")

            except Exception, e:
                traceback.print_exc()

        # Create new Pickle
        if args.c:
            print "Creating local database ..."
            try:
                if os.path.isfile("good_strings.db"):
                    os.remove("good_strings.db")

                good_pickle = set()
                good_pickle = good_strings

                save(good_pickle, "good_strings.db")

                print "New database with %s entries created." % len(good_pickle)
            except Exception, e:
                traceback.print_exc()

    # Use the Database
    else:
        print "Reading goodware strings from database 'good_strings.db' ..."
        try:
            good_pickle = load("good_strings.db")
            # print good_pickle.keys()
            good_strings = good_pickle
        except Exception, e:
            traceback.print_exc()

    # If malware directory given
    if args.m:
        # Scan malware files
        print "Processing malware files ..."
        # Extract all information
        mal_string_stats, file_info_mal = parseMalDir(args.m, args.nr, True, onlyRelevantExtensions)

        # Evaluate Strings
        (file_strings, combinations, super_rules) = malwareStringEvaluation(mal_string_stats, good_strings)

        # Create Rule Files
        (rule_count, super_rule_count) = createRules(file_strings, super_rules, file_info_mal)

        print "Generated %s SIMPLE rules." % str(rule_count)
        if not args.nosuper:
            print "Generated %s SUPER rules." % str(super_rule_count)
        print "All rules written to %s" % args.o
