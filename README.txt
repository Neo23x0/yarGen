#
# Yara BRG
# A Bulk Rule Generator for Yara Rules
#
# Florian Roth
# January 2014

Yara BRG is a generator for Yara rules. The reason why I developed another Yara
rule generator was a special use case in which I had a directory full of 
hackware samples for which I had to write Yara rules. 

=== What does Yara BRG do? 
The main principle is the creation of yara rules from strings found in malware
files while removing all strings that also appear in goodware files. 

Since version 0.6 Yara BRG ships with a goodware strings database that can be 
used to create your rules wihtout scanning any goodware directories and thus
making the process of rule creation much faster.
This way I minimized the chance to trigger false positives with the newly 
generated rules.

The rule generation process tries to identify similarities between the files 
that get analyzed and then combines the strings to so called "super rules". 
Up to now the super rule generation does not remove the simple rule for the
files that have been combined in that single super rule. This means that there
is some redundancy when super rules are created. It is you task to identify
and check the super rules and remove the simple rules matching on a single 
file if the super rule works well for you.

=== Extensions to check

Check line 45 in the code to extend the list of file extensions to check during
the scanning. If you don't get any results, this might be the cause. 

=== Command Line Parameters

usage: yara-brg.py [-h] [-m M] [-g G] [-o output] [-l dir] [-u] -[c] [-rm] [-rg] 
				   [-fs dir] [-rc maxstrings] [--debug]

Yara BRG

optional arguments:
  -m M            Path to scan for malware
  -g G            Path to scan for goodware
  -c			  Create a new database with goodware strings
  -u			  Update the goodware string database
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

= Use the shipped database (FAST) to create some rules

python yara-brg.py -rm -m "X:\MAL\Case1401"

Use the shipped database of goodware strings and scan the malware directory 
"X:\MAL" recursively. Create rules for all files included in this directory and 
below. A file named 'yara_brg_rules.yar' will be generated in the current 
directory.

= Dont use the database and create your own string set from goodware files 
  (behavior in versions pre 0.6)

python yara-brg.py -rm -g C:\Windows\System32 -m "X:\PortScanners"

Scan the System32 directory for goodware samples (-g). Scan the PortScanners
directory for hackware samples (-m) and be recursive in this case (-rm). 
Show debug output. 

= Create a new goodware strings database

python yara-brg.py -c -rg -g C:\Windows\System32

= Update the goodware strings database

python yara-brg.py -u -rg -g "C:\Program Files"
