#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Byte Mapper
# Binary Signature Generator
# 
# Florian Roth
# June 2014
# v0.1a

import os
import sys
import argparse
import re
import traceback
from colorama import Fore, Back, Style
from colorama import init
from hashlib import md5

def getFiles(dir, recursive):
	# Recursive
	if recursive:
		for root, directories, files in os.walk (dir, followlinks=False):
			for filename in files:
				filePath = os.path.join(root,filename)
				yield filePath
	# Non recursive
	else:
		for filename in os.listdir(dir):
			filePath = os.path.join(dir,filename)
			yield filePath
			
def parseDir(dir, recursive, numBytes):

	# Prepare dictionary
	byte_stats = {}
	
	fileCount = 0
	for filePath in getFiles(dir, recursive):
	
		if os.path.isdir(filePath):
			if recursive:
				parseDir(dir, recursive, numBytes)
			continue
	
		with open(filePath, 'r') as file:
			fileCount += 1
			header = file.read(int(numBytes))
	
			pos = 0
			for byte in header:
				pos += 1
				if pos in byte_stats:
					if byte in byte_stats[pos]:
						byte_stats[pos][byte] += 1
					else:
						byte_stats[pos][byte] = 1 
				else:
					#byte_stats.append(pos) 
					byte_stats[pos] = { byte: 1 }

	return byte_stats, fileCount
	
def visiualizeStats(byteStats, fileCount, heatMapMode, byteFiller, bytesPerLine):
	# Settings
	# print fileCount
	
	bytesPrinted = 0
	for byteStat in byteStats:
		
		if args.d:
			print "------------------------"
			print byteStats[byteStat]
		
		byteToPrint = ".."
		countOfByte = 0
		highestValue = 0
		
		# Evaluate the most often occured byte value at this position
		for ( key, val ) in byteStats[byteStat].iteritems():
			if val > highestValue:
				highestValue = val
				byteToPrint = key
				countOfByte = val 
		
		# Heat Map Mode
		if heatMapMode:
			printHeatMapValue(byteToPrint, countOfByte, fileCount, byteFiller)				
			
		# Standard Mode			
		else:
			if countOfByte >= fileCount:
				sys.stdout.write("%s%s" % ( byteToPrint.encode('hex'), byteFiller ))
			else:
				sys.stdout.write("..%s" % byteFiller)
		
		# Line break
		bytesPrinted += 1
		if bytesPrinted >= bytesPerLine:
			sys.stdout.write("\n")
			bytesPrinted = 0
			
	# Print Heat Map Legend
	printHeatLegend(int(fileCount))
				
def printHeatMapValue(byteToPrint, countOfByte, fileCount, byteFiller):
	if args.d:
		print "Count of byte: %s" % countOfByte
		print "File Count: %s" % fileCount	
	if countOfByte == fileCount:
		sys.stdout.write(Fore.GREEN + '%s' % byteToPrint.encode('hex') + Fore.WHITE + '%s' % byteFiller)
	elif countOfByte == fileCount - 1:
		sys.stdout.write(Fore.CYAN + '%s' % byteToPrint.encode('hex') + Fore.WHITE + '%s' % byteFiller)
	elif countOfByte == fileCount - 2:
		sys.stdout.write(Fore.YELLOW + '%s' % byteToPrint.encode('hex') + Fore.WHITE + '%s' % byteFiller)
	elif countOfByte == fileCount - 3:
		sys.stdout.write(Fore.RED + '%s' % byteToPrint.encode('hex') + Fore.WHITE + '%s' % byteFiller)
	elif countOfByte == fileCount - 4:
		sys.stdout.write(Fore.MAGENTA + '%s' % byteToPrint.encode('hex') + Fore.WHITE + '%s' % byteFiller)
	elif countOfByte == fileCount - 5:
		sys.stdout.write(Fore.WHITE + '%s' % byteToPrint.encode('hex') + Fore.WHITE + '%s' % byteFiller)		
	else: 
		sys.stdout.write(Fore.WHITE + Style.DIM + '..' + Fore.WHITE + Style.RESET_ALL + '%s' % byteFiller)
		
def printHeatLegend(fileCount):
	print ""
	print Fore.GREEN + 'GREEN\tContent of all %s files' % str(fileCount) + Fore.WHITE
	if fileCount > 1:
		print Fore.CYAN + 'CYAN\tContent of %s files' % str(fileCount-1) + Fore.WHITE
	if fileCount > 2:
		print Fore.YELLOW + 'YELLOW\tContent of %s files' % str(fileCount-2) + Fore.WHITE
	if fileCount > 3:
		print Fore.RED + 'RED\tContent of %s files' % str(fileCount-3) + Fore.WHITE
	if fileCount > 4:
		print Fore.MAGENTA + 'MAGENTA\tContent of %s files' % str(fileCount-4) + Fore.WHITE
	if fileCount > 5:		
		print Fore.WHITE + 'WHITE\tContent of %s files' % str(fileCount-5) + Fore.WHITE
	if fileCount > 6:		
		print Fore.WHITE + Style.DIM +'..\tNo identical bytes in more than %s files' % str(fileCount-6) + Fore.WHITE + Style.RESET_ALL	
		
# MAIN ################################################################
if __name__ == '__main__':
	
	# Parse Arguments
	parser = argparse.ArgumentParser(description='Yara BSG')
	parser.add_argument('-p', metavar="malware-dir", help='Path to scan for malware')
	parser.add_argument('-r', action='store_true', default=False, help='Be recursive')
	parser.add_argument('-m', action='store_true', default=False, help='Heat map on byte values')
	parser.add_argument('-f', default=" ", metavar="byte-filler", help='character to fill the gap between the bytes (default: \' \')')	
	parser.add_argument('-c', default=None, metavar="num-occurances", help='Print only bytes that occur in at least X of the samples (default: all files; incompatible with heat map mode) ')
	parser.add_argument('-b', default=1024, metavar="bytes", help='Number of bytes to print (default: 1024)')
	parser.add_argument('-l', default=16, metavar="bytes-per-line", help='Number of bytes to print per line (default: 16)')	
	parser.add_argument('-d', action='store_true', default=False, help='Debug Info')
	
	args = parser.parse_args()
	
	# Colorization
	init()
	
	# Parse the Files
	( byteStats, fileCount) = parseDir(args.p, args.r, args.b)
	
	# print byteStats
	if args.c != None and not args.m:
		fileCount = int(args.c)
	
	# Vizualize Byte Stats
	visiualizeStats(byteStats, fileCount, args.m, args.f, args.l)