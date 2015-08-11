/*
	Yara Rule Set
	Author: YarGen Rule Generator
	Date: 2015-08-07
	Identifier: 
*/

import "pe"

rule write_section {
	meta:
		description = "Auto-generated rule - file 15bfdd4f206ed15d78c5c89e782a9448edb8c6c002e478fe50ecebd3e4d8e8dd"
	condition:
		for any i in (0..pe.number_of_sections-1):
		      (pe.sections[i].name == ".reloc" and pe.sections[i].characteristics & pe.SECTION_MEM_WRITE)
}
