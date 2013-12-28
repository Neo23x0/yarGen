#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Yara BRG
# A bulk rule generator for Yara rules
#
# Florian Roth
# December 2013
# v0.3

import os
import sys
import betterwalk
import argparse
import re
import traceback
from hashlib import md5

def getFiles(dir, recursive):
	# Recursive
	if recursive:
		for root, directories, files in betterwalk.walk (dir, followlinks=False):
			for filename in files:
				filePath = os.path.join(root,filename)
				yield filePath
	# Non recursive
	else:
		for filename in os.listdir(dir):
			filePath = os.path.join(dir,filename)
			yield filePath		

def parseDir(dir, recursive=False, generateInfo=False):

	# Prepare dictionary
	string_stats = {}
	file_info = {}
	
	for filePath in getFiles(dir, recursive):				
		# Get Extension
		extension = os.path.splitext(filePath)[1];
		if not extension in [ ".exe", ".dll" ]:
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
		( strings, md5sum ) = extractStrings(filePath, generateInfo)
		
		# Add md5 value
		if generateInfo:
			file_info[filePath] = {}
			file_info[filePath]["md5"] = md5sum
		
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
			
def extractStrings(filePath, generateInfo):
	# String list
	strings = []
	# Read file data
	try:
		f = open(filePath, 'rb')
		filedata = f.read()
		f.close()
		# Generate md5
		md5sum = ""
		if generateInfo:
			md5sum = md5(filedata).hexdigest()
		# Read strings to list
		string = ""
		for byte in filedata:
			if isAscii(byte):
				string += byte 
			else:
				if len(string) >= args.l:
					# Escape string and than add it to the list
					string = string.replace('\\','\\\\')
					string = string.replace('"','\\"')
					if not string in strings:
						strings.append(string)
						if args.debug:
							#print string
							pass
				string = ""
		# Check if last bytes have been string and not yet saved to list
		if len(string) > 0:
			string = string.replace('\\','\\\\')
			string = string.replace('"','\\"')
			if not string in strings:
				strings.append(string)
	except Exception,e:
		if args.debug:
			traceback.print_exc()
		pass
		
	return strings, md5sum
	
def isAscii(b):
	if ord(b)<127 and ord(b)>31 :
		return 1 
	return 0
	
if __name__ == '__main__':
	
	# Parse Arguments
	parser = argparse.ArgumentParser(description='Yara BRG')
	parser.add_argument('-m', required=True, help='Path to scan for malware')
	parser.add_argument('-g', required=True, help='Path to scan for goodware')
	parser.add_argument('-o', help='Output rule file', metavar='output_rule_file', default='yara_brg_rules.yar')
	parser.add_argument('-l', help='Minimal string length to consider', metavar='size', default=6)
	parser.add_argument('-rm', action='store_true', default=False, help='Recursive scan of malware directories')
	parser.add_argument('-rg', action='store_true', default=False, help='Recursive scan of goodware directories')
	parser.add_argument('-fs', help='Max file size to analyze', metavar='dir', default=2000000)
	parser.add_argument('-rc', help='Maximum number of strings per rule (intelligent filtering will be applied)', metavar='maxstrings', default=20)
	parser.add_argument('--debug', action='store_true', default=False, help='Debug output')
	args = parser.parse_args()

	# Scan goodware files
	good_string_stats, file_info_good = parseDir(args.g, args.rg, False)
	
	# Scan malware files
	mal_string_stats, file_info_mal = parseDir(args.m, args.rm, True)
	
	# Generate Stats
	file_strings = {}
	for string in mal_string_stats:
		# if count == 1
		if mal_string_stats[string]["count"] < 4:
			# If string has not been found in good samples
			if not string in good_string_stats:
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
						
	# Apply intelligent filtering
	for filePath in file_strings:
		# Get the count
		string_set = file_strings[filePath]
		string_count = len(file_strings[filePath])
		
		# filter = [ "words", "length" ] # first filter
		filter = "words"
		# This is the only set we have - even if it's a weak one
		last_useful_set = string_set
		
		# As long as too many strings are in the result set		
		while string_count > int(args.rc):
				
			if args.debug:
				print "Filtering: " + filePath
				
			# Length filter
			if filter == "length":
				# Get the shortest string length
				shortest_string_length = len(min(string_set, key=len))
				if args.debug:
					print "BEFORE LENGTH FILTER: Size %s" % len(string_set)
				string_set = [ s for s in string_set if len(s) != shortest_string_length ]
				if args.debug:
					print "AFTER LENGTH FILTER: Size %s" % len(string_set)
					
			# Words filter
			if filter == "words":
				new_string_set = []
				for string in string_set:
					if re.search(r'[qwrtzpsdfghjklxcvbnm][euioa][qwrtzpsdfghjklxcvbnm]', string, re.IGNORECASE):
						new_string_set.append(string)
				# Replace string set
				string_set = new_string_set
				# Now set filter to length
				filter = "length"					

			# Count the new size
			string_count = len(string_set)
			
			# Save the last useful set
			if string_count > 3:
				last_useful_set = string_set
				if args.debug:
					print "Setting last useful set with a length of %s" % str(string_count)
				
		# Replace the original string set with the new one
		file_strings[filePath] = []
		file_strings[filePath] = last_useful_set
				
	# Generate Yara Rule per File
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
			# clean name from all characters that would cause errors
			cleanedName = re.sub('[^\w]', r'_', cleanedName)
			# Check if already printed
			if cleanedName in printed_rules:
				printed_rules[cleanedName] += 1
				cleanedName = cleanedName + "_" + str(printed_rules[cleanedName])
			else:
				printed_rules[cleanedName] = 1
			# Print rule title
			rule += "rule %s {\n" % cleanedName
			rule += "\tmeta:\n"
			rule += "\t\tdescription = \"Auto-generated rule on file %s\"\n" % file
			rule += "\t\tauthor = \"Yara Bulk Rule Generator by Florian Roth\"\n"
			rule += "\t\thash = \"%s\"\n" % file_info_mal[filePath]["md5"]
			rule += "\tstrings:\n"
			for i, string in enumerate(file_strings[filePath]):
				rule += "\t\t$s%s = \"%s\"\n" % ( str(i), string )
			rule += "\tcondition:\n"
			rule += "\t\tall of them\n"		
			rule += "}\n"
			# print rule
			# Add to rules 
			rules += rule
			rule_count += 1
		except Exception, e:
			traceback.print_exc()		
	
	# Write the rules file
	if args.o:
		try:
			fh = open(args.o, 'w')
			fh.write(rules)
			fh.close()
		except Exception, e:
			traceback.print_exc()
	if args.debug:
		print rules
		
	print "Generated %s Yara rules." % str(rule_count)