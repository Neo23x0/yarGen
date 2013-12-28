#
# Yara BRG
# A Bulk Rule Generator for Yara Rules
#
# Florian Roth
# December 2013

Yara BRG is a generator for Yara rules. The reason why I developed another Yara
rule generator was a special use case in which I had a directory full of 
hackware samples for which I had to write Yara rules. 

=== What does Yara BRG do? 
It takes two directories (optionally recursive) and extracts usable strings from 
both of them. One directory contains the hackware/malware samples. The other one
is a directory of trusted files that gets analyzed as well to minimize the 
chance to trigger false positives with the newly generated rules. 
It is called "goodware directory" in the help text.

=== Command Line Parameters

usage: yara-brg.py [-h] -m M -g G [-o output] [-l dir] [-rm] [-rg] [-fs dir]
                   [-rc maxstrings] [--debug]

Yara BRG

required arguments:
  -m M            Path to scan for malware
  -g G            Path to scan for goodware

optional arguments:
  -h, --help      show this help message and exit
  -o output       Output rule file
  -l size         Minimal string length to consider
  -rm             Recursive scan of malware directories
  -rg             Recursive scan of goodware directories
  -fs dir         Max file size to analyze (default: 2000000)
  -rc maxstrings  Maximum number of strings per rule (intelligent filtering
                  will be applied) (default: 20)
  --debug         Debug output
 
=== Examples

python yara-brg.py --debug -rm -g C:\Windows\System32 -m "X:\PortScanners"

Scan the System32 directory for goodware samples (-g). Scan the PortScanners
directory for hackware samples (-m) and be recursive in this case (-rm). 
Show debug output. 