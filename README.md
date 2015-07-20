# yarGen

[![Join the chat at https://gitter.im/Neo23x0/yarGen](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/Neo23x0/yarGen?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

A Rule Generator for Yara Rules

Florian Roth, July 2015

yarGen is a generator for Yara rules. The reason why I developed another Yara
rule generator was a special use case in which I had a directory full of 
hackware samples for which I had to write Yara rules. 

### What does yarGen do?

The main principle is the creation of yara rules from strings found in malware
files while removing all strings that also appear in goodware files. 

Since version 0.14.0 it uses naive-bayes-classifier by Mustafa Atik and Nejdet
Yucesoy in order to classify the string and detect useful words instead of 
compression/encryption garbage.

Since version 0.12.0 yarGen does not completely remove the goodware strings from
the analysis process but includes them with a very low score. The rules will be
included if no better strings can be found and marked with a comment /* Goodware
rule */. Force yarGen to remvoe all goodware strings with --excludegood. Also
since version 0.12.0 yarGen allows to place the "strings.xml" from
[PEstudio](https://winitor.com/) in the program directory in order to apply the
blacklist definition during the string analysis process. You'll get better
results.

The rule generation process tries to identify similarities between the files 
that get analyzed and then combines the strings to so called "super rules". 
Up to now the super rule generation does not remove the simple rule for the
files that have been combined in a single super rule. This means that there
is some redundancy when super rules are created. You can supress a simple rule
for a file that was already covered by super rule by using --nosimple.

### Installation

1. Make sure you have at least 2GB of RAM on the machine you plan to use yarGen
2. Clone the git repository
3. Install all dependancies with ```sudo pip install pickle scandir lxml naiveBayesClassifier```
4. Unzip the goodware database (e.g. ```7z x good-strings.db.zip.001```)
5. See help with ```python yarGen.py --help```

### Memory Requirements

Warning: yarGen pulls the whole goodstring database to memory and uses up to 
2 GB of memory for a few seconds. 

## Command Line Parameters

```
usage: yarGen.py [-h] [-m M] [-l min-size] [-z min-score] [-s max-size]
                 [-rc maxstrings] [--excludegood] [-o output_rule_file]
                 [-a author] [-r ref] [-p prefix] [--score] [--nosimple]
                 [--nomagic] [--nofilesize] [-fm FM] [--noglobal] [--nosuper]
                 [-g G] [-u] [-c] [--nr] [--oe] [-fs size-in-MB] [--debug]
                 [--noop] [-n opcode-num] [--inverse] [--nodirname]
                 [--noscorefilter]

yarGen

optional arguments:
  -h, --help           show this help message and exit

Rule Creation:
  -m M                 Path to scan for malware
  -l min-size          Minimum string length to consider (default=8)
  -z min-score         Minimum score to consider (default=5)
  -s max-size          Maximum length to consider (default=128)
  -rc maxstrings       Maximum number of strings per rule (default=20,
                       intelligent filtering will be applied)
  --excludegood        Force the exclude all goodware strings

Rule Output:
  -o output_rule_file  Output rule file
  -a author            Author Name
  -r ref               Reference
  -p prefix            Prefix for the rule description
  --score              Show the string scores as comments in the rules
  --nosimple           Skip simple rule creation for files included in super
                       rules
  --nomagic            Don't include the magic header condition statement
  --nofilesize         Don't include the filesize condition statement
  -fm FM               Multiplier for the maximum 'filesize' condition
                       (default: 3)
  --noglobal           Don't create global rules
  --nosuper            Don't try to create super rules that match against
                       various files

Database Operations:
  -g G                 Path to scan for goodware (dont use the database
                       shipped with yaraGen)
  -u                   Update local goodware database (use with -g)
  -c                   Create new local goodware database (use with -g)

General Options:
  --nr                 Do not recursively scan directories
  --oe                 Only scan executable extensions EXE, DLL, ASP, JSP,
                       PHP, BIN, INFECTED
  -fs size-in-MB       Max file size in MB to analyze (default=10)
  --debug              Debug output

OpCode Feature:
  --noop               Do not use the OpCode string feature
  -n opcode-num        Number of opcodes to add if not enough high scoring
                       string could be found (default=3)

Inverse Mode:
  --inverse            Show the string scores as comments in the rules
  --nodirname          Don't use the folder name variable in inverse rules
  --noscorefilter      Don't filter strings based on score (default in
                       'inverse' mode)
```

## Best Practice

See the following blog post for a more detailed description on how to use yarGen for YARA rule creation: [How to Write Simple but Sound Yara Rules](https://www.bsk-consulting.de/2015/02/16/write-simple-sound-yara-rules/)
  
## Screenshots

![Generator Run](./screens/yargen-running.png)

![Output Rule](./screens/output-rule-0.14.1.png)

As you can see in the screenshot above you'll get a rule that contains strings, which are not found in the goodware strings database. 

You should clean up the rules afterwards. In the example above, remove the strings $s14, $s17, $s19, $s20 that look like random code to get a cleaner rule that is more likely to match on other samples of the same family. 

To get a more generic rule, remove string $s5, which is very specific for this compiled executable. 
 
## Examples

### Use the shipped database (FAST) to create some rules

```python yarGen.py -m X:\MAL\Case1401```

Use the shipped database of goodware strings and scan the malware directory 
"X:\MAL" recursively. Create rules for all files included in this directory and 
below. A file named 'yargen_rules.yar' will be generated in the current 
directory. 

### Show the score of the strings as comment

yarGen will by default use the top 20 strings based on their score. To see how a
certain string in the rule scored, use the "--score" parameter.

```python yarGen.py --score -m X:\MAL\Case1401```

### Use only strings with a certain minimum score

In order to use only strings for your rules that match a certain minimum score use the "-z" parameter. It is a good pratice to first create rules with "--score" and than perform a second run with a minimum score set for you sample set via "-z".  

```python yarGen.py --score -z 5 -m X:\MAL\Case1401```

### Preset author and reference

```python yarGen.py -a "Florian Roth" -r "http://goo.gl/c2qgFx" -m /opt/mal/case_441 -o case441.yar```

### Exclude strings from Goodware samples

```python yarGen.py --excludegood -m /opt/mal/case_441```

### Supress simple rule if alreay covered by a super rules

```python yarGen.py --nosimple -m /opt/mal/case_441```

### Show debugging output

```python yarGen.py --debug -m /opt/mal/case_441```

### Create a new goodware strings database

```python yarGen.py -c -g C:\Windows\System32```

### Update the goodware strings database (append new strings to the old ones)

```python yarGen.py -u -g "C:\Program Files"```

### Inverse rule creation (still beta)

In order to create some inverse rules on goodware, you have to prepare a directory with subdirectories in which you include all versions of the files you want to create inverse rules for with their original name and in their original folder. If that sounds strange, let me give you an example. 

E.g. you want to create inverse rules for all Windows executables in the System32 folder, you have to create a goodware archive with the following directory structure:

- G:\goodware
  - WindowsXP
    - System32 - all files
  - Windows2003
    - System32 - all files
  - Windows2008R2
    - System32 - all files

yarGen than creates rules that identify e.g. file name "cmd.exe" in path ending with "System32" and checks if the file contains certain necessary strings. If the strings don't show up, the rule will fire. This indicates a replaced system file or malware file that tries to masquerade as a system file. 

```python yarGen.py --inverse -oe -m G:\goodware\```

You can also instruct yarGen not to include the file path but solely rely on the filename. 

```python yarGen.py --inverse -oe --nodirname -m G:\goodware\```
