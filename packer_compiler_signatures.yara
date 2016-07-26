import "pe"
import "math"

rule IsPE32 : PECheck
{
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint16(uint32(0x3C)+0x18) == 0x010B
}

rule IsPE64 : PECheck
{
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint16(uint32(0x3C)+0x18) == 0x020B
}

rule IsNET_EXE : PECheck
{
	condition:
		pe.imports ("mscoree.dll","_CorExeMain")
}

rule IsNET_DLL : PECheck
{
	condition:
		pe.imports ("mscoree.dll","_CorDllMain")
}

rule IsDLL : PECheck
{
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		(uint16(uint32(0x3C)+0x16) & 0x2000) == 0x2000

}

rule IsConsole : PECheck
{
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint16(uint32(0x3C)+0x5C) == 0x0003
}

rule IsWindowsGUI : PECheck
{
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint16(uint32(0x3C)+0x5C) == 0x0002
}

rule IsPacked : PECheck
{
	meta: 
		description = "Entropy Check"
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		math.entropy(0, filesize) > 7.0
}

rule HasOverlay : PECheck
{
	meta: 
		author="_pusher_"
		description = "Overlay Check"
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size) < filesize
}


rule HasDigitalSignature : PECheck
{
	meta: 
		author="_pusher_"
		description = "DigitalSignature Check"
		date="2016-07"
	strings:		
		//size check is wildcarded
		$a0 = { ?? ?? ?? ?? 00 02 02 00 30 82 ?? ?? 06 09 2A 86 48 86 F7 0D 01 07 02 A0 82 ?? ?? 30 82 ?? ?? 02 01 01 31 0B 30 09 06 05 2B 0E 03 02 1A 05 00 30 68 06 0A 2B 06 01 04 01 82 37 02 01 04 A0 5A 30 58 30 33 06 0A 2B 06 01 04 01 82 37 02 01 0F 30 25 03 01 00 A0 20 A2 1E 80 1C 00 3C 00 3C 00 3C 00 4F 00 62 00 73 00 6F 00 6C 00 65 00 74 00 65 00 3E 00 3E 00 3E 30 21 30 09 06 05 2B 0E 03 02 1A 05 00 04 14 }
		$a1 = { ?? ?? ?? ?? 00 02 02 00 30 82 ?? ?? 06 09 2A 86 48 86 F7 0D 01 07 02 A0 82 ?? ?? 30 82 ?? ?? 02 01 01 31 0B 30 09 06 05 2B 0E 03 02 1A 05 00 30 ?? 06 0A 2B 06 01 04 01 82 37 02 01 04 A0 ?? 30 ?? 30 ?? 06 0A 2B 06 01 04 01 82 37 02 01 0F 30 ?? 03 01 00 A0 ?? A2 ?? 80 00 30 21 30 09 06 05 2B 0E 03 02 1A 05 00 04 14 }
		$a2 = { ?? ?? ?? ?? 00 02 02 00 30 82 ?? ?? 06 09 2A 86 48 86 F7 0D 01 07 02 A0 82 ?? ?? 30 82 ?? ?? 02 01 01 31 0E 30 ?? 06 ?? ?? 86 48 86 F7 0D 02 05 05 00 30 67 06 0A 2B 06 01 04 01 82 37 02 01 04 A0 59 30 57 30 33 06 0A 2B 06 01 04 01 82 37 02 01 0F 30 25 03 01 00 A0 20 A2 1E 80 1C 00 3C 00 3C 00 3C 00 4F 00 62 00 73 00 6F 00 6C 00 65 00 74 00 65 00 3E 00 3E 00 3E 30 20 30 0C 06 08 2A 86 48 86 F7 0D 02 05 05 00 04 }
		$a3 = { ?? ?? ?? ?? 00 02 02 00 30 82 ?? ?? 06 09 2A 86 48 86 F7 0D 01 07 02 A0 82 ?? ?? 30 82 ?? ?? 02 01 01 31 0F 30 ?? 06 ?? ?? 86 48 01 65 03 04 02 01 05 00 30 78 06 0A 2B 06 01 04 01 82 37 02 01 04 A0 6A 30 68 30 33 06 0A 2B 06 01 04 01 82 37 02 01 0F 30 25 03 01 00 A0 20 A2 1E 80 1C 00 3C 00 3C 00 3C 00 4F 00 62 00 73 00 6F 00 6C 00 65 00 74 00 65 00 3E 00 3E 00 3E 30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 }
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		(for any of ($a*) : ($ in ( (pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size)..filesize)) )
		//its not always like this:
		//and  uint32(@a0) == (filesize-(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size))
}

rule HasDebugData : PECheck
{
	meta: 
		author = "_pusher_"
		description = "DebugData Check"
		date="2016-07"
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		//orginal
		//((uint32(uint32(0x3C)+0xA8) >0x0) and (uint32be(uint32(0x3C)+0xAC) >0x0))
		//((uint16(uint32(0x3C)+0x18) & 0x200) >> 5) x64/x32
		(IsPE32 or IsPE64) and
		((uint32(uint32(0x3C)+0xA8+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5)) >0x0) and (uint32be(uint32(0x3C)+0xAC+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5)) >0x0))
}

rule IsBeyondImageSize : PECheck
{
	meta: 
		author = "_pusher_"
		date = "2016-07"
		description = "Data Beyond ImageSize Check"
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		for any i in (0..pe.number_of_sections-1):
		((pe.sections[i].virtual_address+pe.sections[i].virtual_size) > (uint32(uint32(0x3C)+0x50)))		
}

rule ImportTableIsBad : PECheck
{
	meta: 
		author = "_pusher_ & mrexodia"
		date = "2016-07"
		description = "ImportTable Check"
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		(IsPE32 or IsPE64) and
		( 		//Import_Table_RVA+Import_Data_Size .. cannot be outside imagesize
		((uint32(uint32(0x3C)+0x80+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5) )) + (uint32(uint32(0x3C)+0x84+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5))))    > (uint32(uint32(0x3C)+0x50))
		)		
}


rule HasModified_DOS_Message : PECheck
{
	meta: 
		author = "_pusher_"
		description = "DOS Message Check"
		date="2016-07"
	strings:	
		$a0 = "This program must be run under Win32" wide ascii nocase
		$a1 = "This program cannot be run in DOS mode" wide ascii nocase
		//UniLink
		$a2 = "This program requires Win32" wide ascii nocase
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and not
		(for any of ($a*) : ($ in (0x0..uint32(0x3c) )))
}

rule HasRichSignature : PECheck
{
	meta: 
		author = "_pusher_"
		description = "Rich Signature Check"
		date="2016-07"
	strings:	
		$a0 = "Rich" ascii
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		(for any of ($a*) : ($ in (0x0..uint32(0x3c) )))
}

rule borland_cpp {
	meta:
		author = "_pusher_"
		description = "Borland C++"
		date = "2015-08"
		version = "0.1"
	strings:
		$c0 = { 59 5F 6A 00 E8 ?? ?? ?? ?? 59 68 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 6A 00 E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? 33 C0 A0 ?? ?? ?? ?? C3 A1 ?? ?? ?? ?? C3 }
		$c1 = { A1 ?? ?? ?? ?? C1 E0 02 A3 ?? ?? ?? ?? 52 6A 00 E8 ?? ?? ?? ?? 8B D0 E8 ?? ?? ?? ?? 5A E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? 59 68 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 6A 00 E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? 33 C0 A0 ?? ?? ?? ?? C3 A1 ?? ?? ?? ?? C3 }
		$c2 = { 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 6A 00 E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? 33 C0 A0 ?? ?? ?? ?? C3 A1 ?? ?? ?? ?? C3 }
	condition:
		(
		//linker 2.25 and 5.00
		((pe.linker_version.major == 2) and (pe.linker_version.minor == 25 )) or
		((pe.linker_version.major == 5) and (pe.linker_version.minor == 0 ))
		) and
		any of them
}

rule borland_delphi {
	meta:
		author = "_pusher_"
		description = "Borland Delphi 2.0 - 7.0 / 2005 - 2007"
		date = "2016-03"
		version = "0.2"
	strings:
		$c0 = { 53 8B D8 33 C0 A3 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? FF A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? 33 C0 A3 }
		$c1 = { 53 8B D8 33 C0 A3 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? 8D 43 08 A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 5B C3 }
		//some x64 version of delphi
		$c2 = { 53 48 83 EC 20 48 89 CB C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 48 33 C9 E8 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8D 43 10 48 89 05 ?? ?? ?? ?? 48 8D 05 ?? FC FF FF 48 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 D9 48 8D 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 }
		//unusual delphi version unknown version (unpackme- FSG 1.31 - dulek)
		$c3 = { 50 6A 00 E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 C7 42 08 00 00 00 00 C7 42 0C 00 00 00 00 E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 }
		//delphi2
		$c4 = { E8 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 0A ?? ?? ?? B8 ?? ?? ?? ?? C3 }
		//delphi3
		$c5 = { 50 6A 00 E8 ?? ?? FF FF BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 55 8B EC 33 C0 }
		//delphi5
		$c6 = { 50 6A ?? E8 ?? ?? FF FF BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 C7 42 08 ?? ?? ?? ?? C7 42 0C ?? ?? ?? ?? E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 }
	condition:
		any of them
		//($c0 or $c1 or $c2 or $c3 or $c4 or $c5 or $c6) 
		and
		(
		//if its not linker 2.25 its been modified (unpacked usually)
												//unknown x64 build of delphi
		((pe.linker_version.major == 2) and (pe.linker_version.minor == 25 )) or ((pe.linker_version.major == 8) and (pe.linker_version.minor == 0 ))
		//unpacked files usually have this linker:
		or ((pe.linker_version.major == 0) and (pe.linker_version.minor == 0 )) )
}

rule free_pascal {
	meta:
		author = "_pusher_"
		description = "Free Pascal"
		date = "2015-08"
		version = "0.1"
	strings:
		$c0 = { 55 89 E5 83 ?? ?? 89 5D FC B8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? A0 ?? ?? ?? ?? 84 C0 75 0C 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 }
		$c1 = { 55 89 E5 53 B8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 80 3D ?? ?? ?? ?? 00 75 0C 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? B8 }
		$c2 = { 55 89 E5 83 EC 04 89 5D FC B8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A0 ?? ?? ?? ?? 84 C0 75 05 E8 ?? ?? ?? ?? C7 05 }
	condition:
		any of them
}

rule borland_delphi_dll {
	meta:
		author = "_pusher_"
		description = "Borland Delphi DLL"
		date = "2015-08"
		version = "0.1"
		info = "one is at entrypoint"
	strings:
		$c0 = { BA ?? ?? ?? ?? 83 7D 0C 01 75 ?? 50 52 C6 05 ?? ?? ?? ?? ?? 8B 4D 08 89 0D ?? ?? ?? ?? 89 4A 04 }
		$c1 = { 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 ?? ?? FF FF E8 ?? ?? FF FF 8D 40 00 }
	condition:
		any of them
}

rule borland_component {
	meta:
		author = "_pusher_"
		description = "Borland Component"
		date = "2015-08"
		version = "0.1"
	strings:
		$c0 = { E9 ?? ?? ?? FF 8D 40 00 }
	condition:
		$c0 at pe.entry_point
}

rule PureBasic : Neil Hodgson
{
      	meta:
		author="_pusher_"
		date="2016-07"
	strings:
		$c0 = { 55 8B EC 6A 00 68 00 10 00 00 6A ?? FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 10 00 00 00 A1 ?? ?? ?? ?? 50 6A ?? 8B 0D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 5D C3 CC CC CC CC CC CC CC CC CC }
		$c1 = { 68 ?? ?? 00 00 68 00 00 00 00 68 ?? ?? ?? 00 E8 ?? ?? ?? 00 83 C4 0C 68 00 00 00 00 E8 ?? ?? ?? 00 A3 ?? ?? ?? 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 ?? ?? ?? 00 A3 }
	condition:
		(for any of ($c0,$c1) : ( $ at pe.entry_point  )) and ((pe.linker_version.major == 2) and (pe.linker_version.minor == 50 ))
}

rule PureBasicDLL : Neil Hodgson
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 83 7C 24 08 01 75 ?? 8B 44 24 04 A3 ?? ?? ?? 10 E8 }

condition:
		$a0 at pe.entry_point
}

rule PureBasic4xDLL : Neil Hodgson
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 83 7C 24 08 01 75 0E 8B 44 24 04 A3 ?? ?? ?? 10 E8 22 00 00 00 83 7C 24 08 02 75 00 83 7C 24 08 00 75 05 E8 ?? 00 00 00 83 7C 24 08 03 75 00 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 ?? 0F 00 00 A3 }

condition:
		$a0 at pe.entry_point
}

rule SkDUndetectabler : SkDrat {
	meta:
		author = "_pusher_"
	condition:
		(
		borland_delphi or //check All FSG or
		((pe.linker_version.major == 6) and (pe.linker_version.minor == 0 ))
		)
		and
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size < filesize) and
		//is overlay at offset 2A00,1A00,C00,745,739
		//pe.overlay & pe.overlay_size would have been prettier
		( 
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size == 0x00000739)  or
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size == 0x00000745)  or
		//Uncompressed
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size == 0x00000C00)  or
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size == 0x00002A00)  or
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size == 0x00001A00)
		)
		and
		//is xored MZ ?
		( 
		uint16(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size) == 0x6275 or
		uint16(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size) == 0x4057
		)
}

rule MicrosoftVisualCV80
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 6A 14 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BB 94 00 00 00 53 6A 00 8B ?? ?? ?? ?? ?? FF D7 50 FF ?? ?? ?? ?? ?? 8B F0 85 F6 75 0A 6A 12 E8 ?? ?? ?? ?? 59 EB 18 89 1E 56 FF ?? ?? ?? ?? ?? 56 85 C0 75 14 50 FF D7 50 FF ?? ?? ?? ?? ?? B8 }

condition:
		$a0 at pe.entry_point
}

rule MinGWGCC3x
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? ?? ?? E8 ?? ?? FF FF ?? ?? ?? ?? ?? ?? ?? ?? 55 }

condition:
		$a0 at pe.entry_point
}

rule FASM : flat assembler {
//abit weak, needs more targets & testing
	meta:
		author = "_pusher_"
		date = "2016-01"
		description = "http://flatassembler.net"
	//strings:
		//$c0 = { 55 89 E5 83 EC 1C 8D 45 E4 6A 1C 50 FF 75 08 FF 15 ?? ?? ?? ?? 8B 45 E8 C9 C2 04 00 }
	condition:
		(
		//linker 1.60..1.79
		(pe.linker_version.major == 1) and (pe.linker_version.minor >= 60) and (pe.linker_version.minor < 80) 
		) 
		//and $c0
}

rule masm32_tasm32
{
	meta:
		author = "PEiD"
		description = "MASM32 / TASM32"
		group = "20"
		function = "0"
	strings:
		$a0 = { 6A ?? E8 ?? ?? ?? ?? A3 }
	condition:
		$a0
}
