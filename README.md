# yarGen

A Rule Generator for Yara Rules

Florian Roth, April 2016

yarGen is a generator for [YARA](https://github.com/plusvic/yara/) rules

### What does yarGen do?

The main principle is the creation of yara rules from strings found in malware
files while removing all strings that also appear in goodware files. Therefore 
yarGen includes a big goodware strings and opcode database as ZIP archives that 
have to be extracted before the first use. 

Since version 0.12.0 yarGen does not completely remove the goodware strings from
the analysis process but includes them with a very low score. The rules will be
included if no better strings can be found and marked with a comment /* Goodware
rule */. Force yarGen to remvoe all goodware strings with --excludegood. Also
since version 0.12.0 yarGen allows to place the "strings.xml" from
[PEstudio](https://winitor.com/) in the program directory in order to apply the
blacklist definition during the string analysis process. You'll get better
results.

Since version 0.14.0 it uses naive-bayes-classifier by Mustafa Atik and Nejdet
Yucesoy in order to classify the string and detect useful words instead of 
compression/encryption garbage.

Since version 0.15.0 yarGen supports opcode elements extracted from the
.text sections of PE files. During database creation it splits the .text 
sections with the regex [\x00]{3,} and takes the first 16 bytes of each part 
to build an opcode database from goodware PE files. During rule creation on
sample files it compares the goodware opcodes with the opcodes extracted from
the malware samples and removes all opcodes that also appear in the goodware
database. (there is no further magic in it yet - no XOR loop detection etc.)
The option to activate opcode integration is '--opcodes'. 

Since version 0.16.0 yarGen supports the Binarly. Binarly is a "binary search 
engine" that can search arbitrary byte patterns through the contents of tens 
of millions of samples, instantly. It allows you to quickly get answers to 
questions like “What other files contain this code/string?” or “Can this 
code/string be found in clean applications or malware samples?”. This means 
that you can use Binarly to quickly verify the quality of your YARA strings.
Furthermore, Binarly has a YARA file search functionality, which you can 
use to scan their entire collection (currently at 7.5+ Million PE files, 3.5M 
clean - over 6TB) with your rule in a less than a minute.
For yarGen I integrated their [public API](https://github.com/binarlyhq/binarly-sdk).
In order to be able to use it you just need an API key that you can get for 
free if you contact them at contact@binar.ly. The option to activate binarly
lookups is '--binarly'.

The rule generation process als tries to identify similarities between the 
files that get analyzed and then combines the strings to so called "super rules".
Up to now the super rule generation does not remove the simple rule for the
files that have been combined in a single super rule. This means that there
is some redundancy when super rules are created. You can supress a simple rule
for a file that was already covered by super rule by using --nosimple.

### Installation

1. Make sure you have at least 3GB of RAM on the machine you plan to use yarGen (5GB if opcodes should be included in rule generation, use with --opcodes)
2. Clone the git repository
3. Install all dependancies with ```sudo pip install scandir lxml naiveBayesClassifier pefile``` (@twpDone reported that in case of errors try ```sudo pip install pefile``` and ```sudo pip3 install scandir lxml naiveBayesClassifier```)
4. Clone and install [Binarly-SDK](https://github.com/binarlyhq/binarly-sdk/) and install it with ```python ./setup.py install```
5. Unzip the goodware string database (e.g. ```7z x good-strings.db.zip.001```)
6. Unzip the goodware opcode database (e.g. ```7z x good-opcodes.db.zip.001```)
7. See help with ```python yarGen.py --help```

### Memory Requirements

Warning: yarGen pulls the whole goodstring database to memory and uses up to 
3 GB of memory for a few seconds - 5 GB if opcode evaluation is used. 

I already tried to migrate the database to sqlite but the numerous string 
comparisons and lookups made the analysis very slow.

## Binarly

In order to use the Binarly lookup, you need an API key placed in a file named 
```apikey.txt``` in the ```./config``` subfolder. 

Request an Binarly API key by mail to: contact@binar.ly  

## Command Line Parameters

```
usage: yarGen.py [-h] [-m M] [-l min-size] [-z min-score] [-x high-scoring]
                 [-s max-size] [-rc maxstrings] [--excludegood]
                 [-o output_rule_file] [-a author] [-r ref] [-p prefix]
                 [--score] [--nosimple] [--nomagic] [--nofilesize] [-fm FM]
                 [--globalrule] [--nosuper] [-g G] [-u] [-c] [--nr] [--oe]
                 [-fs size-in-MB] [--debug] [--opcodes] [-n opcode-num]
                 [--binarly]

yarGen

optional arguments:
  -h, --help           show this help message and exit

Rule Creation:
  -m M                 Path to scan for malware
  -l min-size          Minimum string length to consider (default=8)
  -z min-score         Minimum score to consider (default=5)
  -x high-scoring      Score required to set string as 'highly specific
                       string' (default: 30, +10 with binarly)
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
  -fm FM               Multiplier for the maximum 'filesize' condition value
                       (default: 3)
  --globalrule         Create global rules (improved rule set speed)
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

Other Features:
  --opcodes            Do use the OpCode feature (use this if not enough high
                       scoring strings can be found)
  -n opcode-num        Number of opcodes to add if not enough high scoring
                       string could be found (default=3)
  --binarly            Use binarly to lookup string statistics
```

## Best Practice

See the following blog posts for a more detailed description on how to use yarGen for YARA rule creation: 

[How to Write Simple but Sound Yara Rules - Part 1](https://www.bsk-consulting.de/2015/02/16/write-simple-sound-yara-rules/)
[How to Write Simple but Sound Yara Rules - Part 2](https://www.bsk-consulting.de/2015/10/17/how-to-write-simple-but-sound-yara-rules-part-2/)
[How to Write Simple but Sound Yara Rules - Part 3](https://www.bsk-consulting.de/2016/04/15/how-to-write-simple-but-sound-yara-rules-part-3/)
  
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

### My Best Pratice Command Line

```python yarGen.py --debug --score --binarly -z 3 /opt/mal/APTx/samples```