rule CRC32_poly_Constants
{
	meta:
		author = "_pusher_"
		description = "Look for CRC32 [poly]"
		date = "2015-05"
		version = "0.1"
	strings:
		$c1 = { 2083B8ED }
	condition:
		1 of them
}

rule CRC32_table
{
	meta:
		author = "_pusher_"
		description = "Look for CRC32 table"
		date = "2015-05"
		version = "0.1"
	strings:
		$pattern = { 00 00 00 00 96 30 07 77 2C 61 0E EE BA 51 09 99 19 C4 6D 07 }
	condition:
		$pattern
}

rule Elf_Hash
{
	meta:
		author = "_pusher_"
		description = "Look for ElfHash"
		date = "2015-06"
		version = "0.1"
	strings:
		$c0 = { 53 56 33 C9 8B DA 4B 85 DB 7C 25 43 C1 E1 04 33 D2 8A 10 03 CA 8B D1 81 E2 00 00 00 F0 85 D2 74 07 8B F2 C1 EE 18 33 CE F7 D2 23 CA 40 4B 75 DC 8B C1 5E 5B C3 }
		$c1 = { 53 33 D2 85 C0 74 2B EB 23 C1 E2 04 81 E1 FF 00 00 00 03 D1 8B CA 81 E1 00 00 00 F0 85 C9 74 07 8B D9 C1 EB 18 33 D3 F7 D1 23 D1 40 8A 08 84 C9 75 D7 8B C2 5B C3 }
		$c2 = { 53 56 33 C9 8B D8 85 D2 76 23 C1 E1 04 33 C0 8A 03 03 C8 8B C1 25 00 00 00 F0 85 C0 74 07 8B F0 C1 EE 18 33 CE F7 D0 23 C8 43 4A 75 DD 8B C1 5E 5B C3 }
		$c3 = { 53 56 57 8B F2 8B D8 8B FB 53 E8 ?? ?? ?? ?? 6B C0 02 71 05 E8 ?? ?? ?? ?? 8B D7 33 C9 8B D8 83 EB 01 71 05 E8 ?? ?? ?? ?? 85 DB 7C 2C 43 C1 E1 04 0F B6 02 03 C8 71 05 E8 ?? ?? ?? ?? 83 C2 01 B8 00 00 00 F0 23 C1 85 C0 74 07 8B F8 C1 EF 18 33 CF F7 D0 23 C8 4B 75 D5 8B C1 99 F7 FE 8B C2 85 C0 7D 09 03 C6 71 05 E8 ?? ?? ?? ?? 5F 5E 5B C3 }
	condition:
		any of them
}

rule BLOWFISH_Constants
{
	meta:
		author = "phoul (@phoul)"
		description = "Look for Blowfish constants"
		date = "2014-01"
		version = "0.1"
	strings:
		$c0 = { D1310BA6 }
		$c1 = { A60B31D1 }
		$c2 = { 98DFB5AC }
		$c3 = { ACB5DF98 }
		$c4 = { 2FFD72DB }
		$c5 = { DB72FD2F }
		$c6 = { D01ADFB7 }
		$c7 = { B7DF1AD0 }
		$c8 = { 4B7A70E9 }
		$c9 = { E9707A4B }
		$c10 = { F64C261C }
		$c11 = { 1C264CF6 }
	condition:
		6 of them
}

rule MD5_Constants
{
	meta:
		author = "phoul (@phoul)"
		description = "Look for MD5 constants"
		date = "2014-01"
		version = "0.2"
	strings:
		// Init constants
		$c0 = { 67452301 }
		$c1 = { efcdab89 }
		$c2 = { 98badcfe }
		$c3 = { 10325476 }
		$c4 = { 01234567 }
		$c5 = { 89ABCDEF }
		$c6 = { FEDCBA98 }
		$c7 = { 76543210 }
		// Round 2
		$c8 = { F4D50d87 }
		$c9 = { 78A46AD7 }
	condition:
		5 of them
}

rule RC6_Constants
{
	meta:
		author = "chort (@chort0)"
		description = "Look for RC6 magic constants in binary"
		reference = "https://twitter.com/mikko/status/417620511397400576"
		reference2 = "https://twitter.com/dyngnosis/status/418105168517804033"
		date = "2013-12"
		version = "0.2"
	strings:
		$c1 = { B7E15163 }
		$c2 = { 9E3779B9 }
		$c3 = { 6351E1B7 }
		$c4 = { B979379E }
	condition:
		2 of them
}

rule RIPEMD160_Constants
{
	meta:
		author = "phoul (@phoul)"
		description = "Look for RIPEMD-160 constants"
		date = "2014-01"
		version = "0.1"
	strings:
		$c0 = { 67452301 }
		$c1 = { EFCDAB89 }
		$c2 = { 98BADCFE }
		$c3 = { 10325476 }
		$c4 = { C3D2E1F0 }
		$c5 = { 01234567 }
		$c6 = { 89ABCDEF }
		$c7 = { FEDCBA98 }
		$c8 = { 76543210 }
		$c9 = { F0E1D2C3 }
	condition:
		5 of them
}
rule SHA1_Constants
{
	meta:
		author = "phoul (@phoul)"
		description = "Look for SHA1 constants"
		date = "2014-01"
		version = "0.1"
	strings:
		$c0 = { 67452301 }
		$c1 = { EFCDAB89 }
		$c2 = { 98BADCFE }
		$c3 = { 10325476 }
		$c4 = { C3D2E1F0 }
		$c5 = { 01234567 }
		$c6 = { 89ABCDEF }
		$c7 = { FEDCBA98 }
		$c8 = { 76543210 }
		$c9 = { F0E1D2C3 }
	condition:
		5 of them
}

rule SHA512_Constants
{
	meta:
		author = "phoul (@phoul)"
		description = "Look for SHA384/SHA512 constants"
		date = "2014-01"
		version = "0.1"
	strings:
		$c0 = { 428a2f98 }
		$c1 = { 982F8A42 }
		$c2 = { 71374491 }
		$c3 = { 91443771 }
		$c4 = { B5C0FBCF }
		$c5 = { CFFBC0B5 }
		$c6 = { E9B5DBA5 }
		$c7 = { A5DBB5E9 }
		$c8 = { D728AE22 }
		$c9 = { 22AE28D7 }
	condition:
		5 of them
}

rule WHIRLPOOL_Constants
{
	meta:
		author = "phoul (@phoul)"
		description = "Look for WhirlPool constants"
		date = "2014-02"
		version = "0.1"
	strings:
		$c0 = { 18186018c07830d8 }
		$c1 = { d83078c018601818 }
		$c2 = { 23238c2305af4626 }
		$c3 = { 2646af05238c2323 }
	condition:
		2 of them
}

rule DarkEYEv3_Cryptor
{
	meta:
		description = "Rule to detect DarkEYEv3 encrypted executables (often malware)"
		author = "Florian Roth"
		reference = "http://darkeyev3.blogspot.fi/"
		date = "2015-05-24"
		hash0 = "6b854b967397f7de0da2326bdd5d39e710e2bb12"
		hash1 = "d53149968eca654fc0e803f925e7526fdac2786c"
		hash2 = "7e3a8940d446c57504d6a7edb6445681cca31c65"
		hash3 = "d3dd665dd77b02d7024ac16eb0949f4f598299e7"
		hash4 = "a907a7b74a096f024efe57953c85464e87275ba3"
		hash5 = "b1c422155f76f992048377ee50c79fe164b22293"
		hash6 = "29f5322ce5e9147f09e0a86cc23a7c8dc88721b9"
		hash7 = "a0382d7c12895489cb37efef74c5f666ea750b05"
		hash8 = "f3d5b71b7aeeb6cc917d5bb67e2165cf8a2fbe61"
		score = 55
	strings:
		$s0 = "\\DarkEYEV3-" 
	condition:
		uint16(0) == 0x5a4d and $s0
}

rule Miracl_powmod
{	meta:
		author = "Maxx"
		description = "Miracl powmod"
	strings:
		$pattern = { 53 55 56 57 E8 ?? ?? ?? ?? 8B F0 8B 86 18 02 00 00 85 C0 0F 85 EC 01 00 00 8B 56 1C 42 8B C2 89 56 1C 83 F8 18 7D 17 C7 44 86 20 12 00 00 00 8B 86 2C 02 00 00 85 C0 74 05 E8 ?? ?? ?? ?? 8B 06 8B 4E 10 3B C1 74 2E 8B 7C 24 1C 57 E8 ?? ?? ?? ?? 83 C4 04 83 F8 02 7C 33 8B 57 04 8B 0E 51 8B 02 50 E8 ?? ?? ?? ?? 83 C4 08 83 F8 01 0F 84 58 01 00 00 EB 17 8B 7C 24 1C 6A 02 57 E8 ?? ?? ?? ?? 83 C4 08 85 C0 0F 84 3F 01 00 00 8B 8E C4 01 00 00 8B 54 24 18 51 52 E8 ?? ?? ?? ?? 8B 86 CC }
	condition:
		$pattern
}

rule Miracl_crt
{	meta:
		author = "Maxx"
		description = "Miracl crt"
	strings:
		$pattern = { 51 56 57 E8 ?? ?? ?? ?? 8B 74 24 10 8B F8 89 7C 24 08 83 7E 0C 02 0F 8C 99 01 00 00 8B 87 18 02 00 00 85 C0 0F 85 8B 01 00 00 8B 57 1C 42 8B C2 89 57 1C 83 F8 18 7D 17 C7 44 87 20 4A 00 00 00 8B 87 2C 02 00 00 85 C0 74 05 E8 ?? ?? ?? ?? 8B 46 04 8B 54 24 14 53 55 8B 08 8B 02 51 50 E8 ?? ?? ?? ?? 8B 4E 0C B8 01 00 00 00 83 C4 08 33 ED 3B C8 89 44 24 18 0F 8E C5 00 00 00 BF 04 00 00 00 8B 46 04 8B 0C 07 8B 10 8B 44 24 1C 51 52 8B 0C 07 51 E8 ?? ?? ?? ?? 8B 56 04 8B 4E 08 8B 04 }
	condition:
		$pattern
}

rule CryptoPP_a_exp_b_mod_c
{	meta:
		author = "Maxx"
		description = "CryptoPP a_exp_b_mod_c"
	strings:
		$pattern1 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 81 EC ?? 00 00 00 56 8B B4 24 B0 00 00 00 57 6A 00 8B CE C7 44 24 0C 00 00 00 00 E8 ?? ?? ?? ?? 84 C0 0F 85 16 01 00 00 8D 4C 24 24 E8 ?? ?? ?? ?? BF 01 00 00 00 56 8D 4C 24 34 89 BC 24 A4 00 00 00 E8 ?? ?? ?? ?? 8B 06 8D 4C 24 3C 50 6A 00 C6 84 24 A8 00 00 00 02 E8 ?? ?? ?? ?? 8D 4C 24 48 C6 84 24 A0 00 00 00 03 E8 ?? ?? ?? ?? C7 44 24 24 ?? ?? ?? ?? 8B 8C 24 AC 00 00 00 8D 54 24 0C 51 52 8D 4C 24 2C C7 84 24 A8 }
		$pattern2 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 4C 56 57 33 FF 8D 44 24 0C 89 7C 24 08 C7 44 24 10 ?? ?? ?? ?? C7 44 24 0C ?? ?? ?? ?? 89 44 24 14 8B 74 24 70 8D 4C 24 18 56 89 7C 24 60 E8 ?? ?? ?? ?? 8B 76 08 8D 4C 24 2C 56 57 C6 44 24 64 01 E8 ?? ?? ?? ?? 8D 4C 24 40 C6 44 24 5C 02 E8 ?? ?? ?? ?? C7 44 24 0C ?? ?? ?? ?? 8B 4C 24 6C 8B 54 24 68 8B 74 24 64 51 52 56 8D 4C 24 18 C7 44 24 68 03 00 00 00 E8 ?? ?? ?? ?? 8B 7C 24 4C 8B 4C 24 48 8B D7 33 C0 F3 }
		$pattern3 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 34 56 57 33 FF 8D 44 24 0C 89 7C 24 08 C7 44 24 10 ?? ?? ?? ?? C7 44 24 0C ?? ?? ?? ?? 89 44 24 14 8B 74 24 58 8D 4C 24 18 56 89 7C 24 48 E8 ?? ?? ?? ?? 8B 0E C6 44 24 44 01 51 57 8D 4C 24 2C E8 ?? ?? ?? ?? 8D 4C 24 30 C6 44 24 44 02 E8 ?? ?? ?? ?? C7 44 24 0C ?? ?? ?? ?? 8B 54 24 54 8B 44 24 50 8B 74 24 4C 52 50 56 8D 4C 24 18 C7 44 24 50 03 00 00 00 E8 ?? ?? ?? ?? 8B 4C 24 30 8B 7C 24 34 33 C0 F3 AB 8B 4C }
	condition:
		any of them
}

rule CryptoPP_modulo
{	meta:
		author = "Maxx"
		description = "CryptoPP modulo"
	strings:
		$pattern1 = { 83 EC 20 53 55 8B 6C 24 2C 8B D9 85 ED 89 5C 24 08 75 18 8D 4C 24 0C E8 ?? ?? ?? ?? 8D 44 24 0C 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 4D FF 56 85 CD 57 75 09 8B 53 04 8B 02 23 C1 EB 76 8B CB E8 ?? ?? ?? ?? 83 FD 05 8B C8 77 2D 33 F6 33 FF 49 85 C0 74 18 8B 53 04 8D 41 01 8D 14 8A 8B 0A 03 F1 83 D7 00 48 83 EA 04 85 C0 77 F1 6A 00 55 57 56 E8 ?? ?? ?? ?? EB 3B 33 C0 8B D1 49 85 D2 74 32 8B 54 24 10 33 DB 8D 71 01 8B 52 04 8D 3C 8A 8B 17 33 ED 0B C5 8B 6C 24 34 33 C9 53 0B CA 55 }
		$pattern2 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 2C 56 57 8B F1 33 FF 8D 4C 24 20 89 7C 24 08 E8 ?? ?? ?? ?? 8D 4C 24 0C 89 7C 24 3C E8 ?? ?? ?? ?? 8B 44 24 48 8D 4C 24 0C 50 56 8D 54 24 28 51 52 C6 44 24 4C 01 E8 ?? ?? ?? ?? 8B 74 24 54 83 C4 10 8D 44 24 20 8B CE 50 E8 ?? ?? ?? ?? 8B 7C 24 18 8B 4C 24 14 8B D7 33 C0 F3 AB 52 E8 ?? ?? ?? ?? 8B 7C 24 30 8B 4C 24 2C 8B D7 33 C0 C7 44 24 10 ?? ?? ?? ?? 52 F3 AB E8 ?? ?? ?? ?? 8B 4C 24 3C 83 C4 08 8B C6 64 89 }
		$pattern3 = { 83 EC 24 53 55 8B 6C 24 30 8B D9 85 ED 89 5C 24 08 75 18 8D 4C 24 0C E8 ?? ?? ?? ?? 8D 44 24 0C 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 4D FF 56 85 CD 57 75 09 8B 53 0C 8B 02 23 C1 EB 76 8B CB E8 ?? ?? ?? ?? 83 FD 05 8B C8 77 2D 33 F6 33 FF 49 85 C0 74 18 8B 53 0C 8D 41 01 8D 14 8A 8B 0A 03 F1 83 D7 00 48 83 EA 04 85 C0 77 F1 6A 00 55 57 56 E8 ?? ?? ?? ?? EB 3B 33 C0 8B D1 49 85 D2 74 32 8B 54 24 10 33 DB 8D 71 01 8B 52 0C 8D 3C 8A 8B 17 33 ED 0B C5 8B 6C 24 38 33 C9 53 0B CA 55 }
		$pattern4 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 1C 56 57 8B F1 33 FF 8D 4C 24 0C 89 7C 24 08 E8 ?? ?? ?? ?? 8D 4C 24 18 89 7C 24 2C E8 ?? ?? ?? ?? 8B 44 24 38 8D 4C 24 18 50 56 8D 54 24 14 51 52 C6 44 24 3C 01 E8 ?? ?? ?? ?? 8B 74 24 44 83 C4 10 8D 44 24 0C 8B CE 50 E8 ?? ?? ?? ?? 8B 4C 24 18 8B 7C 24 1C 33 C0 F3 AB 8B 4C 24 1C 51 E8 ?? ?? ?? ?? 8B 4C 24 10 8B 7C 24 14 33 C0 F3 AB 8B 54 24 14 52 E8 ?? ?? ?? ?? 8B 4C 24 2C 83 C4 08 8B C6 64 89 0D 00 00 00 }
	condition:
		any of them
}

rule FGint_MontgomeryModExp1
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint MontgomeryModExp1"
	strings:
		$pattern = { 55 8B EC 83 C4 ?? 53 56 57 33 DB 89 5D ?? 8B F1 8B DA 89 45 ?? 8B 7D 08 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 D4 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CF 8B D6 8B 45 FC E8 ?? ?? ?? ?? 8D 55 D4 8B C7 E8 ?? ?? ?? ?? 3C 02 75 0D 8D 45 D4 E8 ?? ?? ?? ?? E9 }
	condition:
		$pattern
}

rule FGint_MontgomeryModExp2
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint MontgomeryModExp2"
	strings:
		$pattern = { 55 8B EC 83 C4 ?? 53 56 57 33 DB 89 5D ?? 8B F1 8B DA 89 45 ?? 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 D4 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CF 8B D6 8B 45 FC E8 ?? ?? ?? ?? 8D 55 D4 8B C7 E8 ?? ?? ?? ?? 3C 02 75 0D 8D 45 D4 E8 ?? ?? ?? ?? E9 }
	condition:
		$pattern
}

rule FGint_MontgomeryModExp3
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint MontgomeryModExp3"
	strings:
		$pattern = { 55 8B EC 83 C4 ?? 53 56 57 33 DB 89 5D ?? 8B F1 8B DA 89 45 ?? 8B 7D 08 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 D4 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CF 8B D6 8B 45 ?? E8 ?? ?? ?? ?? 8D 55 D4 8B C7 E8 ?? ?? ?? ?? 3C 02 75 0D 8D 45 D4 E8 ?? ?? ?? ?? E9 }
	condition:
		$pattern
}

rule FGint_MontgomeryModExp4
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint MontgomeryModExp4"
	strings:
		$pattern = { 55 8B EC 83 C4 ?? 53 56 57 33 DB 89 5D ?? 8B F1 8B DA 89 45 D0 8B 7D 08 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 47 4C 47 00 64 FF 30 64 89 20 8D 55 D4 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CF 8B D6 8B 45 D0 E8 ?? ?? ?? ?? 8D 55 D4 8B C7 E8 ?? ?? ?? ?? 3C 02 75 0D 8D 45 D4 E8 ?? ?? ?? ?? E9 02 02 00 00 }
	condition:
		$pattern
}

rule FGint_FGIntModExp
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint FGIntModExp"
	strings:
		$pattern = { 55 8B EC 83 C4 E8 53 56 57 33 DB 89 5D ?? 8B F1 89 55 ?? 8B D8 8B 7D 08 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 46 04 8B 40 04 83 E0 01 83 F8 01 75 0F 57 8B CE 8B 55 ?? 8B C3 E8 ?? ?? ?? ?? EB ?? 8D 55 ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B D7 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 55 F4 8B C3 E8 ?? ?? ?? ?? 8B 45 }
	condition:
		$pattern
}

rule FGint_MulByInt
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint MulByInt"
	strings:
		$pattern = { 53 56 57 55 83 C4 E8 89 4C 24 04 8B EA 89 04 24 8B 04 24 8B 40 04 8B 00 89 44 24 08 8B 44 24 08 83 C0 02 50 8D 45 04 B9 01 00 00 00 8B 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 C4 04 33 F6 8B 7C 24 08 85 FF 76 6D BB 01 00 00 00 8B 04 24 8B 40 04 8B 04 98 33 D2 89 44 24 10 89 54 24 14 8B 44 24 04 33 D2 52 50 8B 44 24 18 8B 54 24 1C ?? ?? ?? ?? ?? 89 44 24 10 89 54 24 14 8B C6 33 D2 03 44 24 10 13 54 24 14 89 44 24 10 89 54 24 14 8B 44 24 10 25 FF FF FF 7F 8B 55 04 89 04 9A 8B 44 24 10 8B 54 24 14 0F AC D0 1F C1 EA 1F 8B F0 43 4F 75 98 }
	condition:
		$pattern
}

rule FGint_DivMod
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint FGIntDivMod"
	strings:
		$pattern = { 55 8B EC 83 C4 BC 53 56 57 8B F1 89 55 F8 89 45 FC 8B 5D 08 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 45 FC 8A 00 88 45 D7 8B 45 F8 8A 00 88 45 D6 8B 45 FC E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? 8B D3 8B 45 FC E8 ?? ?? ?? ?? 8D 55 E0 8B 45 F8 E8 ?? ?? ?? ?? 8B 55 F8 8B 45 FC }
	condition:
		$pattern
}

rule FGint_FGIntDestroy
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint FGIntDestroy"
	strings:
		$pattern = { 53 8B D8 8D 43 04 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5B C3 }
	condition:
		$pattern
}

rule FGint_Base10StringToGInt
{	meta:
		author = "_pusher_"
		description = "FGint Base10StringToGInt"
	strings:
		$pattern = { 55 8B EC B9 04 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 8B DA 89 45 FC 8B 45 FC ?? ?? ?? ?? ?? 33 C0 55 ?? ?? ?? ?? ?? 64 FF 30 64 89 20 EB 12 8D 45 FC B9 01 00 00 00 BA 01 00 00 00 ?? ?? ?? ?? ?? 8B 45 FC 8A 00 2C 2D 74 11 04 FD 2C 0A 72 0B 8B 45 FC ?? ?? ?? ?? ?? 48 7F D4 8D 45 E4 50 B9 01 00 00 00 BA 01 00 00 00 8B 45 FC ?? ?? ?? ?? ?? 8B 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 75 18 C6 45 EB 00 8D 45 FC B9 01 00 00 00 BA 01 00 00 00 ?? ?? ?? ?? ?? EB 18 C6 45 EB 01 EB 12 8D 45 FC }
	condition:
		$pattern
}

rule FGint_ConvertBase256to64
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint ConvertBase256to64"
	strings:
		$pattern = { 55 8B EC 81 C4 EC FB FF FF 53 56 57 33 C9 89 8D EC FB FF FF 89 8D F0 FB FF FF 89 4D F8 8B FA 89 45 FC B9 00 01 00 00 8D 85 F4 FB FF FF 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 85 F4 FB FF FF BA FF 00 00 00 E8 ?? ?? ?? ?? 8D 45 F8 E8 ?? ?? ?? ?? 8B 45 FC E8 ?? ?? ?? ?? 8B D8 85 DB 7E 2F BE 01 00 00 00 8D 45 F8 8B 55 FC 0F B6 54 32 FF 8B 94 95 F4 FB FF FF E8 ?? ?? ?? ?? 46 4B 75 E5 EB }
	condition:
		$pattern
}

rule FGint_ConvertHexStringToBase256String
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint ConvertHexStringToBase256String"
	strings:
		$pattern = { 55 8B EC 83 C4 F0 53 56 33 C9 89 4D F0 89 55 F8 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 45 F8 E8 ?? ?? ?? ?? 8B 45 FC E8 ?? ?? ?? ?? D1 F8 79 03 83 D0 00 85 C0 7E 5F 89 45 F4 BE 01 00 00 00 8B C6 03 C0 8B 55 FC 8A 54 02 FF 8B 4D FC 8A 44 01 FE 3C 3A 73 0A 8B D8 80 EB 30 C1 E3 04 EB 08 8B D8 80 EB 37 C1 E3 04 80 FA 3A 73 07 80 EA 30 0A DA EB 05 80 EA 37 0A DA 8D 45 F0 8B D3 }
	condition:
		$pattern
}

rule FGint_Base256StringToGInt
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint Base256StringToGInt"
	strings:
		$pattern = { 55 8B EC 81 C4 F8 FB FF FF 53 56 57 33 C9 89 4D F8 8B FA 89 45 FC 8B 45 FC ?? ?? ?? ?? ?? B9 00 01 00 00 8D 85 F8 FB FF FF 8B 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C0 55 ?? ?? ?? ?? ?? 64 FF 30 64 89 20 8D 45 F8 ?? ?? ?? ?? ?? 8D 85 F8 FB FF FF BA FF 00 00 00 ?? ?? ?? ?? ?? 8B 45 FC ?? ?? ?? ?? ?? 8B D8 85 DB 7E 34 BE 01 00 00 00 8D 45 F8 8B 55 FC 0F B6 54 32 FF 8B 94 95 F8 FB FF FF ?? ?? ?? ?? ?? 46 4B 75 E5 EB 12 8D 45 F8 B9 01 00 00 00 BA 01 00 00 00 ?? ?? ?? ?? ?? 8B 45 F8 80 38 30 75 0F }
	condition:
		$pattern
}

rule FGint_FGIntToBase256String
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint FGIntToBase256String"
	strings:
		$pattern = { 55 8B EC 33 C9 51 51 51 51 53 56 8B F2 33 D2 55 68 ?? ?? ?? ?? 64 FF 32 64 89 22 8D 55 FC E8 ?? ?? ?? ?? EB 10 8D 45 FC 8B 4D FC BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 FC E8 ?? ?? ?? ?? 25 07 00 00 80 79 05 48 83 C8 F8 40 85 C0 75 D8 8B 45 FC E8 ?? ?? ?? ?? 8B D8 85 DB 79 03 83 C3 07 C1 FB 03 8B C6 E8 ?? ?? ?? ?? 85 DB 76 4B 8D 45 F4 50 B9 08 00 00 00 BA 01 00 00 00 8B 45 FC E8 ?? ?? ?? ?? 8B 55 F4 8D 45 FB E8 ?? ?? ?? ?? 8D 45 F0 8A 55 FB E8 ?? ?? ?? ?? 8B 55 F0 8B C6 E8 ?? ?? ?? ?? 8D 45 FC B9 08 00 00 00 BA 01 00 00 00 E8 ?? ?? ?? ?? 4B 75 B5 }
	condition:
		$pattern
}

rule FGint_ConvertBase256StringToHexString
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint ConvertBase256StringToHexString"
	strings:
		$pattern = { 55 8B EC 33 C9 51 51 51 51 51 51 53 56 57 8B F2 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B C6 E8 ?? ?? ?? ?? 8B 45 FC E8 ?? ?? ?? ?? 8B F8 85 FF 0F 8E AB 00 00 00 C7 45 F8 01 00 00 00 8B 45 FC 8B 55 F8 8A 5C 10 FF 33 C0 8A C3 C1 E8 04 83 F8 0A 73 1E 8D 45 F4 33 D2 8A D3 C1 EA 04 83 C2 30 E8 ?? ?? ?? ?? 8B 55 F4 8B C6 E8 ?? ?? ?? ?? EB 1C 8D 45 F0 33 D2 8A D3 C1 EA 04 83 C2 37 E8 ?? ?? ?? ?? 8B 55 F0 8B C6 E8 ?? ?? ?? ?? 8B C3 24 0F 3C 0A 73 22 8D 45 EC 8B D3 80 E2 0F 81 E2 FF 00 00 00 83 C2 30 E8 ?? ?? ?? ?? 8B 55 EC 8B C6 E8 ?? ?? ?? ?? EB 20 8D 45 E8 8B D3 80 E2 0F 81 E2 FF 00 00 00 83 C2 37 }
	condition:
		$pattern
}

rule FGint_RSAEncrypt
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint RSAEncrypt"
	strings:
		$pattern = { 55 8B EC 83 C4 D0 53 56 57 33 DB 89 5D D0 89 5D DC 89 5D D8 89 5D D4 8B F9 89 55 F8 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 E0 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 55 DC 8B C7 E8 ?? ?? ?? ?? 8B 45 DC E8 ?? ?? ?? ?? 8B D8 8D 55 DC 8B 45 FC E8 ?? ?? ?? ?? 8D 45 DC 8B 4D DC BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F3 4E EB 10 }
	condition:
		$pattern
}

rule FGint_RsaDecrypt
{	meta:
		author = "Maxx"
		description = "FGint RsaDecrypt"
	strings:
		$pattern = { 55 8B EC 83 C4 A0 53 56 57 33 DB 89 5D A0 89 5D A4 89 5D A8 89 5D B4 89 5D B0 89 5D AC 89 4D F8 8B FA 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 B8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 }
	condition:
		$pattern
}

rule DES_Long
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "DES [long]"
	strings:
		$pattern = { 10 80 10 40 00 00 00 00 00 80 10 00 00 00 10 40 10 00 00 40 10 80 00 00 00 80 00 40 00 80 10 00 00 80 00 00 10 00 10 40 10 00 00 00 00 80 00 40 10 00 10 00 00 80 10 40 00 00 10 40 10 00 00 00 }
	condition:
		$pattern
}

rule DES_pbox_long
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "DES [pbox] [long]"
	strings:
		$pattern = { 0F 00 00 00 06 00 00 00 13 00 00 00 14 00 00 00 1C 00 00 00 0B 00 00 00 1B 00 00 00 10 00 00 00 00 00 00 00 0E 00 00 00 16 00 00 00 19 00 00 00 04 00 00 00 11 00 00 00 1E 00 00 00 09 00 00 00 01 00 00 00 07 00 00 00 17 00 00 00 0D 00 00 00 1F 00 00 00 1A 00 00 00 02 00 00 00 08 00 00 00 12 00 00 00 0C 00 00 00 1D 00 00 00 05 00 00 00 }
	condition:
		$pattern
}

rule OpenSSL_BN_mod_exp2_mont
{	meta:
		author = "Maxx"
		description = "OpenSSL BN_mod_exp2_mont"
	strings:
		$pattern = { B8 30 05 00 00 E8 ?? ?? ?? ?? 8B 84 24 48 05 00 00 53 33 DB 56 8B 08 57 89 5C 24 24 89 5C 24 30 8A 01 89 5C 24 28 A8 01 89 5C 24 0C 75 24 68 89 00 00 00 68 ?? ?? ?? ?? 6A 66 6A 76 6A 03 E8 ?? ?? ?? ?? 83 C4 14 33 C0 5F 5E 5B 81 C4 30 05 00 00 C3 8B 94 24 48 05 00 00 52 E8 ?? ?? ?? ?? 8B F0 8B 84 24 54 05 00 00 50 E8 ?? ?? ?? ?? 83 C4 08 3B F3 8B F8 75 20 3B FB 75 1C 8B 8C 24 40 05 00 00 6A 01 51 E8 ?? ?? ?? ?? 83 C4 08 5F 5E 5B 81 C4 30 05 00 00 C3 3B F7 89 74 24 18 7F 04 89 }
	condition:
		$pattern
}

rule OpenSSL_BN_mod_exp_mont
{	meta:
		author = "Maxx"
		description = "OpenSSL BN_mod_exp_mont"
	strings:
		$pattern = { B8 A0 02 00 00 E8 ?? ?? ?? ?? 53 56 57 8B BC 24 BC 02 00 00 33 F6 8B 07 89 74 24 24 89 74 24 20 89 74 24 0C F6 00 01 75 24 68 72 01 00 00 68 ?? ?? ?? ?? 6A 66 6A 6D 6A 03 E8 ?? ?? ?? ?? 83 C4 14 33 C0 5F 5E 5B 81 C4 A0 02 00 00 C3 8B 8C 24 B8 02 00 00 51 E8 ?? ?? ?? ?? 8B D8 83 C4 04 3B DE 89 5C 24 18 75 1C 8B 94 24 B0 02 00 00 6A 01 52 E8 ?? ?? ?? ?? 83 C4 08 5F 5E 5B 81 C4 A0 02 00 00 C3 55 8B AC 24 C4 02 00 00 55 E8 ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 8B F0 55 89 74 24 24 E8 }
	condition:
		$pattern
}

rule OpenSSL_BN_mod_exp_recp
{	meta:
		author = "Maxx"
		description = "OpenSSL BN_mod_exp_recp"
	strings:
		$pattern = { B8 C8 02 00 00 E8 ?? ?? ?? ?? 8B 84 24 D4 02 00 00 55 56 33 F6 50 89 74 24 1C 89 74 24 18 E8 ?? ?? ?? ?? 8B E8 83 C4 04 3B EE 89 6C 24 0C 75 1B 8B 8C 24 D4 02 00 00 6A 01 51 E8 ?? ?? ?? ?? 83 C4 08 5E 5D 81 C4 C8 02 00 00 C3 53 57 8B BC 24 EC 02 00 00 57 E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 8B D8 83 C4 08 3B DE 0F 84 E7 02 00 00 8D 54 24 24 52 E8 ?? ?? ?? ?? 8B B4 24 EC 02 00 00 83 C4 04 8B 46 0C 85 C0 74 32 56 53 E8 ?? ?? ?? ?? 83 C4 08 85 C0 0F 84 BA 02 00 00 57 8D 44 24 28 53 }
	condition:
		$pattern
}

rule OpenSSL_BN_mod_exp_simple
{	meta:
		author = "Maxx"
		description = "OpenSSL BN_mod_exp_simple"
	strings:
		$pattern = { B8 98 02 00 00 E8 ?? ?? ?? ?? 8B 84 24 A4 02 00 00 55 56 33 ED 50 89 6C 24 1C 89 6C 24 18 E8 ?? ?? ?? ?? 8B F0 83 C4 04 3B F5 89 74 24 0C 75 1B 8B 8C 24 A4 02 00 00 6A 01 51 E8 ?? ?? ?? ?? 83 C4 08 5E 5D 81 C4 98 02 00 00 C3 53 57 8B BC 24 BC 02 00 00 57 E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 8B D8 83 C4 08 3B DD 0F 84 71 02 00 00 8D 54 24 28 52 E8 ?? ?? ?? ?? 8B AC 24 BC 02 00 00 8B 84 24 B4 02 00 00 57 55 8D 4C 24 34 50 51 C7 44 24 30 01 00 00 00 E8 ?? ?? ?? ?? 83 C4 14 85 C0 0F }
	condition:
		$pattern
}

rule OpenSSL_BN_mod_exp_inverse
{	meta:
		author = "Maxx"
		description = "OpenSSL BN_mod_exp_inverse"
	strings:
		$pattern = { B8 18 00 00 00 E8 ?? ?? ?? ?? 53 55 56 57 8B 7C 24 38 33 C0 57 89 44 24 20 89 44 24 24 E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 57 89 44 24 1C E8 ?? ?? ?? ?? 57 8B F0 E8 ?? ?? ?? ?? 57 89 44 24 28 E8 ?? ?? ?? ?? 57 8B E8 E8 ?? ?? ?? ?? 57 8B D8 E8 ?? ?? ?? ?? 8B F8 8B 44 24 54 50 89 7C 24 38 E8 ?? ?? ?? ?? 83 C4 20 89 44 24 24 85 C0 8B 44 24 2C 0F 84 78 05 00 00 85 C0 75 05 E8 ?? ?? ?? ?? 85 C0 89 44 24 1C 0F 84 63 05 00 00 8B 4C 24 14 6A 01 51 E8 ?? ?? ?? ?? 6A 00 57 E8 }
	condition:
		$pattern
}

rule FGint_RsaSign
{	meta:
		author = "Maxx"
		description = "FGint RsaSign"
	strings:
		$pattern = { 55 8B EC 83 C4 B8 53 56 57 89 4D F8 8B FA 89 45 FC 8B 75 0C 8B 5D 10 8B 45 FC E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 B8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 F0 }
	condition:
		$pattern
}

rule FGint_RsaVerify
{	meta:
		author = "Maxx"
		description = "FGint RsaVerify"
	strings:
		$pattern = { 55 8B EC 83 C4 E0 53 56 8B F1 89 55 F8 89 45 FC 8B 5D 0C 8B 45 FC E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 E8 8B 45 F8 E8 ?? ?? ?? ?? 8D 55 F0 8B 45 FC E8 ?? ?? ?? ?? 8D 4D E0 8B D3 8D 45 F0 E8 ?? ?? ?? ?? 8D 55 F0 8D 45 E0 E8 ?? ?? ?? ?? 8D 45 E0 50 8B CB 8B D6 8D 45 E8 E8 ?? ?? ?? ?? 8D 55 E8 8D 45 E0 E8 }
	condition:
		$pattern
}

rule LockBox_RsaEncryptFile
{	meta:
		author = "Maxx"
		description = "LockBox RsaEncryptFile"
	strings:
		$pattern = { 55 8B EC 83 C4 F8 53 56 8B F1 8B DA 6A 20 8B C8 B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 FC 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 68 FF FF 00 00 8B CB B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 F8 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8A 45 08 50 8B CE 8B 55 F8 8B 45 FC E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule LockBox_DecryptRsaEx
{	meta:
		author = "Maxx"
		description = "LockBox DecryptRsaEx"
	strings:
		$pattern = { 55 8B EC 83 C4 F4 53 56 57 89 4D F8 89 55 FC 8B D8 33 C0 8A 43 04 0F B7 34 45 ?? ?? ?? ?? 0F B7 3C 45 ?? ?? ?? ?? 8B CE B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 F4 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 55 FC 8B CE 8B 45 F4 E8 ?? ?? ?? ?? 6A 00 B1 02 8B D3 8B 45 F4 E8 ?? ?? ?? ?? 8B 45 F4 E8 ?? ?? ?? ?? 3B C7 7E 16 B9 ?? ?? ?? ?? B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 F4 E8 ?? ?? ?? ?? 8B C8 8B 55 F8 8B 45 F4 E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 }
	condition:
		$pattern
}

rule LockBox_EncryptRsaEx
{	meta:
		author = "Maxx"
		description = "LockBox EncryptRsaEx"
	strings:
		$pattern = { 55 8B EC 83 C4 F8 53 56 57 89 4D FC 8B FA 8B F0 33 C0 8A 46 04 0F B7 1C 45 ?? ?? ?? ?? 8B CB B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 F8 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B D7 8B 4D 08 8B 45 F8 E8 ?? ?? ?? ?? 6A 01 B1 02 8B D6 8B 45 F8 E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? 3B C3 7E 16 B9 ?? ?? ?? ?? B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? 8B C8 8B 55 FC 8B 45 F8 E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8B 45 F8 E8 }
	condition:
		$pattern
}

rule LockBox_TlbRsaKey
{	meta:
		author = "Maxx"
		description = "LockBox TlbRsaKey"
	strings:
		$pattern = { 53 56 84 D2 74 08 83 C4 F0 E8 ?? ?? ?? ?? 8B DA 8B F0 33 D2 8B C6 E8 ?? ?? ?? ?? 33 C0 8A 46 04 8B 15 ?? ?? ?? ?? 0F B7 0C 42 B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 46 0C 33 C0 8A 46 04 8B 15 ?? ?? ?? ?? 0F B7 0C 42 B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 46 10 8B C6 84 DB 74 0F E8 ?? ?? ?? ?? 64 8F 05 00 00 00 00 83 C4 0C 8B C6 5E 5B C3 }
	condition:
		$pattern
}

rule BigDig_bpInit
{	meta:
		author = "Maxx"
		description = "BigDig bpInit"
	strings:
		$pattern = { 56 8B 74 24 0C 6A 04 56 E8 ?? ?? ?? ?? 8B C8 8B 44 24 10 83 C4 08 85 C9 89 08 75 04 33 C0 5E C3 89 70 08 C7 40 04 00 00 00 00 5E C3 }
	condition:
		$pattern
}

rule BigDig_mpModExp
{	meta:
		author = "Maxx"
		description = "BigDig mpModExp"
	strings:
		$pattern = { 56 8B 74 24 18 85 F6 75 05 83 C8 FF 5E C3 53 55 8B 6C 24 18 57 56 55 E8 ?? ?? ?? ?? 8B D8 83 C4 08 BF 00 00 00 80 8B 44 9D FC 85 C7 75 04 D1 EF 75 F8 83 FF 01 75 08 BF 00 00 00 80 4B EB 02 D1 EF 8B 44 24 18 56 8B 74 24 18 50 56 E8 ?? ?? ?? ?? 83 C4 0C 85 DB 74 4F 8D 6C 9D FC 8B 4C 24 24 8B 54 24 20 51 52 56 56 56 E8 ?? ?? ?? ?? 8B 45 00 83 C4 14 85 C7 74 19 8B 44 24 24 8B 4C 24 20 8B 54 24 18 50 51 52 56 56 E8 ?? ?? ?? ?? 83 C4 14 83 FF 01 75 0B 4B BF 00 00 00 80 83 ED 04 EB }
	condition:
		$pattern
}

rule BigDig_mpModInv
{	meta:
		author = "Maxx"
		description = "BigDig mpModInv"
	strings:
		$pattern = { 81 EC 2C 07 00 00 8D 84 24 CC 00 00 00 53 56 8B B4 24 44 07 00 00 57 56 6A 01 50 E8 ?? ?? ?? ?? 8B 8C 24 4C 07 00 00 56 8D 94 24 80 02 00 00 51 52 E8 ?? ?? ?? ?? 8D 84 24 BC 01 00 00 56 50 E8 ?? ?? ?? ?? 8B 9C 24 64 07 00 00 56 8D 4C 24 30 53 51 E8 ?? ?? ?? ?? 8D 54 24 38 56 52 BF 01 00 00 00 E8 ?? ?? ?? ?? 83 C4 34 85 C0 0F 85 ED 00 00 00 8D 44 24 0C 56 50 8D 8C 24 78 02 00 00 56 8D 94 24 48 03 00 00 51 8D 84 24 18 04 00 00 52 50 E8 ?? ?? ?? ?? 8D 8C 24 BC 01 00 00 56 8D 94 }
	condition:
		$pattern
}

rule BigDig_mpModMult
{	meta:
		author = "Maxx"
		description = "BigDig mpModMult"
	strings:
		$pattern = { 8B 44 24 0C 8B 4C 24 08 81 EC 98 01 00 00 8D 54 24 00 56 8B B4 24 B0 01 00 00 57 56 50 51 52 E8 ?? ?? ?? ?? 8B 84 24 C0 01 00 00 8B 94 24 B4 01 00 00 8D 3C 36 56 50 8D 4C 24 20 57 51 52 E8 ?? ?? ?? ?? 8D 44 24 2C 57 50 E8 ?? ?? ?? ?? 83 C4 2C 33 C0 5F 5E 81 C4 98 01 00 00 C3 }
	condition:
		$pattern
}

rule BigDig_mpModulo
{	meta:
		author = "Maxx"
		description = "BigDig mpModulo"
	strings:
		$pattern = { 8B 44 24 10 81 EC 30 03 00 00 8B 8C 24 38 03 00 00 8D 54 24 00 56 8B B4 24 40 03 00 00 57 8B BC 24 4C 03 00 00 57 50 56 51 8D 84 24 B0 01 00 00 52 50 E8 ?? ?? ?? ?? 8B 94 24 54 03 00 00 8D 4C 24 20 57 51 52 E8 ?? ?? ?? ?? 8D 44 24 2C 56 50 E8 ?? ?? ?? ?? 8D 8C 24 CC 01 00 00 56 51 E8 ?? ?? ?? ?? 83 C4 34 33 C0 5F 5E 81 C4 30 03 00 00 C3 }
	condition:
		$pattern
}

rule BigDig_spModExpB
{	meta:
		author = "Maxx"
		description = "BigDig spModExpB"
	strings:
		$pattern = { 53 8B 5C 24 10 55 56 BE 00 00 00 80 85 F3 75 04 D1 EE 75 F8 8B 6C 24 14 8B C5 D1 EE 89 44 24 18 74 48 57 8B 7C 24 20 EB 04 8B 44 24 1C 57 50 50 8D 44 24 28 50 E8 ?? ?? ?? ?? 83 C4 10 85 F3 74 14 8B 4C 24 1C 57 55 8D 54 24 24 51 52 E8 ?? ?? ?? ?? 83 C4 10 D1 EE 75 D0 8B 44 24 14 8B 4C 24 1C 5F 5E 89 08 5D 33 C0 5B C3 8B 54 24 10 5E 5D 5B 89 02 33 C0 C3 }
	condition:
		$pattern
}

rule BigDig_spModInv
{	meta:
		author = "Maxx"
		description = "BigDig spModInv"
	strings:
		$pattern = { 51 8B 4C 24 10 55 56 BD 01 00 00 00 33 F6 57 8B 7C 24 18 89 6C 24 0C 85 C9 74 42 53 8B C7 33 D2 F7 F1 8B C7 8B F9 8B DA 33 D2 F7 F1 8B CB 0F AF C6 03 C5 8B EE 8B F0 8B 44 24 10 F7 D8 85 DB 89 44 24 10 75 D7 85 C0 5B 7D 13 8B 44 24 1C 8B 4C 24 14 2B C5 5F 89 01 5E 33 C0 5D 59 C3 8B 54 24 14 5F 5E 33 C0 89 2A 5D 59 C3 }
	condition:
		$pattern
}

rule BigDig_spModMult
{	meta:
		author = "Maxx"
		description = "BigDig spModMult"
	strings:
		$pattern = { 8B 44 24 0C 8B 4C 24 08 83 EC 08 8D 54 24 00 50 51 52 E8 ?? ?? ?? ?? 8B 44 24 24 6A 02 8D 4C 24 10 50 51 E8 ?? ?? ?? ?? 8B 54 24 24 89 02 33 C0 83 C4 20 C3 }
	condition:
		$pattern
}

rule CryptoPP_ApplyFunction
{	meta:
		author = "Maxx"
		description = "CryptoPP ApplyFunction"
	strings:
		$pattern1 = { 51 8D 41 E4 56 8B 74 24 0C 83 C1 F0 50 51 8B 4C 24 18 C7 44 24 0C 00 00 00 00 51 56 E8 ?? ?? ?? ?? 83 C4 10 8B C6 5E 59 C2 08 00 }
		$pattern2 = { 51 53 56 8B F1 57 6A 00 C7 44 24 10 00 00 00 00 8B 46 04 8B 48 04 8B 5C 31 04 8D 7C 31 04 E8 ?? ?? ?? ?? 50 8B CF FF 53 10 8B 44 24 18 8D 56 08 83 C6 1C 52 56 8B 74 24 1C 50 56 E8 ?? ?? ?? ?? 83 C4 10 8B C6 5F 5E 5B 59 C2 08 00 }
	condition:
		any of them
}

rule CryptoPP_RsaFunction
{	meta:
		author = "Maxx"
		description = "CryptoPP RsaFunction"
	strings:
		$pattern1 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 81 EC 9C 00 00 00 8B 84 24 B0 00 00 00 53 55 56 33 ED 8B F1 57 3B C5 89 B4 24 A8 00 00 00 89 6C 24 10 BF 01 00 00 00 74 18 C7 06 ?? ?? ?? ?? C7 46 20 ?? ?? ?? ?? 89 7C 24 10 89 AC 24 B4 00 00 00 8D 4E 04 E8 ?? ?? ?? ?? 8D 4E 10 89 BC 24 B4 00 00 00 E8 ?? ?? ?? ?? 8B 06 BB ?? ?? ?? ?? BF ?? ?? ?? ?? 8B 48 04 C7 04 31 ?? ?? ?? ?? 8B 16 8B 42 04 8B 54 24 10 83 CA 02 8D 48 E0 89 54 24 10 89 4C 30 FC 89 5C 24 18 89 7C }
		$pattern2 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 08 8B 44 24 1C 53 8B 5C 24 1C 56 8B F1 57 33 C9 89 74 24 10 3B C1 89 4C 24 0C 74 7B C7 46 04 ?? ?? ?? ?? C7 46 3C ?? ?? ?? ?? C7 46 30 ?? ?? ?? ?? C7 46 34 ?? ?? ?? ?? 3B D9 75 06 89 4C 24 28 EB 0E 8B 43 04 8B 50 0C 8D 44 1A 04 89 44 24 28 8B 56 3C C7 44 24 0C 07 00 00 00 8B 42 04 C7 44 30 3C ?? ?? ?? ?? 8B 56 3C 8B 42 08 C7 44 30 3C ?? ?? ?? ?? 8B 56 3C C7 46 38 ?? ?? ?? ?? 8B 42 04 C7 44 30 3C }
		$pattern3 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 08 8B 44 24 18 56 8B F1 57 85 C0 89 74 24 0C C7 44 24 08 00 00 00 00 74 63 C7 46 04 ?? ?? ?? ?? C7 46 3C ?? ?? ?? ?? C7 46 30 ?? ?? ?? ?? C7 46 34 ?? ?? ?? ?? 8B 46 3C C7 44 24 08 07 00 00 00 8B 48 04 C7 44 31 3C ?? ?? ?? ?? 8B 56 3C 8B 42 08 C7 44 30 3C ?? ?? ?? ?? 8B 4E 3C C7 46 38 ?? ?? ?? ?? 8B 51 04 C7 44 32 3C ?? ?? ?? ?? 8B 46 3C 8B 48 08 C7 44 31 3C ?? ?? ?? ?? C7 06 ?? ?? ?? ?? 8D 7E 04 6A 00 8B CF }
	condition:
		any of them
}

rule CryptoPP_Integer_constructor
{	meta:
		author = "Maxx"
		description = "CryptoPP Integer constructor"
	strings:
		$pattern1 = { 8B 44 24 08 56 83 F8 08 8B F1 77 09 8B 14 85 ?? ?? ?? ?? EB 37 83 F8 10 77 07 BA 10 00 00 00 EB 2B 83 F8 20 77 07 BA 20 00 00 00 EB 1F 83 F8 40 77 07 BA 40 00 00 00 EB 13 48 50 E8 ?? ?? ?? ?? BA 01 00 00 00 8B C8 83 C4 04 D3 E2 8D 04 95 00 00 00 00 89 16 50 E8 ?? ?? ?? ?? 8B 4C 24 0C 89 46 04 C7 46 08 00 00 00 00 89 08 8B 0E 8B 46 04 83 C4 04 49 74 0F 57 8D 78 04 33 C0 F3 AB 8B C6 5F 5E C2 08 00 8B C6 5E C2 08 00 }
		$pattern2 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 51 56 8B F1 89 74 24 04 C7 06 ?? ?? ?? ?? 6A 08 C7 44 24 14 00 00 00 00 C7 46 08 02 00 00 00 E8 ?? ?? ?? ?? 89 46 0C C7 46 10 00 00 00 00 C7 06 ?? ?? ?? ?? 8B 46 0C 83 C4 04 C7 40 04 00 00 00 00 8B 4E 0C 8B C6 5E C7 01 00 00 00 00 8B 4C 24 04 64 89 0D 00 00 00 00 83 C4 10 C3 }
		$pattern3 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 51 56 8B F1 57 89 74 24 08 C7 06 ?? ?? ?? ?? 8B 7C 24 1C C7 44 24 14 00 00 00 00 8B CF E8 ?? ?? ?? ?? 83 F8 08 77 09 8B 14 85 ?? ?? ?? ?? EB 37 83 F8 10 77 07 BA 10 00 00 00 EB 2B 83 F8 20 77 07 BA 20 00 00 00 EB 1F 83 F8 40 77 07 BA 40 00 00 00 EB 13 48 50 E8 ?? ?? ?? ?? BA 01 00 00 00 8B C8 83 C4 04 D3 E2 85 D2 89 56 08 76 12 8D 04 95 00 00 00 00 50 E8 ?? ?? ?? ?? 83 C4 04 EB 02 33 C0 89 46 0C 8B 4F 10 89 4E 10 }
		$pattern4 = { 56 57 8B 7C 24 0C 8B F1 8B CF E8 ?? ?? ?? ?? 83 F8 08 77 09 8B 14 85 ?? ?? ?? ?? EB 37 83 F8 10 77 07 BA 10 00 00 00 EB 2B 83 F8 20 77 07 BA 20 00 00 00 EB 1F 83 F8 40 77 07 BA 40 00 00 00 EB 13 48 50 E8 ?? ?? ?? ?? BA 01 00 00 00 8B C8 83 C4 04 D3 E2 8D 04 95 00 00 00 00 89 16 50 E8 ?? ?? ?? ?? 8B 16 89 46 04 8B 4F 08 83 C4 04 89 4E 08 8B 4F 04 85 D2 76 0D 2B C8 8B 3C 01 89 38 83 C0 04 4A 75 F5 8B C6 5F 5E C2 04 00 }
	condition:
		any of them
}

rule RsaRef2_NN_modExp
{	meta:
		author = "Maxx"
		description = "RsaRef2 NN_modExp"
	strings:
		$pattern = { 81 EC 1C 02 00 00 53 55 56 8B B4 24 30 02 00 00 57 8B BC 24 44 02 00 00 57 8D 84 24 A4 00 00 00 56 50 E8 ?? ?? ?? ?? 8B 9C 24 4C 02 00 00 57 53 8D 8C 24 B4 00 00 00 56 8D 94 24 3C 01 00 00 51 52 E8 ?? ?? ?? ?? 57 53 8D 84 24 4C 01 00 00 56 8D 8C 24 D4 01 00 00 50 51 E8 ?? ?? ?? ?? 8D 54 24 50 57 52 E8 ?? ?? ?? ?? 8B 84 24 78 02 00 00 8B B4 24 74 02 00 00 50 56 C7 44 24 60 01 00 00 00 E8 ?? ?? ?? ?? 8D 48 FF 83 C4 44 8B E9 89 4C 24 18 85 ED 0F 8C AF 00 00 00 8D 34 AE 89 74 24 }
	condition:
		any of them
}

rule RsaRef2_NN_modInv
{	meta:
		author = "Maxx"
		description = "RsaRef2 NN_modInv"
	strings:
		$pattern = { 81 EC A4 04 00 00 53 56 8B B4 24 BC 04 00 00 57 8D 84 24 ?? 00 00 00 56 50 E8 ?? ?? ?? ?? 8D 8C 24 1C 01 00 00 BF 01 00 00 00 56 51 89 BC 24 A0 00 00 00 E8 ?? ?? ?? ?? 8B 94 24 C8 04 00 00 56 8D 84 24 AC 01 00 00 52 50 E8 ?? ?? ?? ?? 8B 9C 24 D8 04 00 00 56 8D 4C 24 2C 53 51 E8 ?? ?? ?? ?? 8D 54 24 34 56 52 E8 ?? ?? ?? ?? 83 C4 30 85 C0 0F 85 ED 00 00 00 8D 44 24 0C 56 50 8D 8C 24 A0 01 00 00 56 8D 94 24 AC 02 00 00 51 8D 84 24 34 03 00 00 52 50 E8 ?? ?? ?? ?? 8D 8C 24 2C 01 }
	condition:
		$pattern
}

rule RsaRef2_NN_modMult
{	meta:
		author = "Maxx"
		description = "RsaRef2 NN_modMult"
	strings:
		$pattern = { 8B 44 24 0C 8B 4C 24 08 81 EC 08 01 00 00 8D 54 24 00 56 8B B4 24 20 01 00 00 56 50 51 52 E8 ?? ?? ?? ?? 8B 84 24 2C 01 00 00 56 8D 0C 36 50 8B 84 24 28 01 00 00 8D 54 24 1C 51 52 50 E8 ?? ?? ?? ?? 68 08 01 00 00 8D 4C 24 2C 6A 00 51 E8 ?? ?? ?? ?? 83 C4 30 5E 81 C4 08 01 00 00 C3 }
	condition:
		$pattern
}

rule RsaRef2_RsaPrivateDecrypt
{	meta:
		author = "Maxx"
		description = "RsaRef2 RsaPrivateDecrypt"
	strings:
		$pattern = { 8B 44 24 14 81 EC 84 00 00 00 8B 8C 24 94 00 00 00 56 8B 30 83 C6 07 C1 EE 03 3B CE 76 0D B8 06 04 00 00 5E 81 C4 84 00 00 00 C3 50 8B 84 24 98 00 00 00 51 8D 4C 24 0C 50 8D 54 24 14 51 52 E8 ?? ?? ?? ?? 83 C4 14 85 C0 0F 85 8B 00 00 00 39 74 24 04 74 0D B8 06 04 00 00 5E 81 C4 84 00 00 00 C3 8A 44 24 08 84 C0 75 6B 8A 4C 24 09 B8 02 00 00 00 3A C8 75 5E 8D 4E FF 3B C8 76 0D 8A 54 04 08 84 D2 74 05 40 3B C1 72 F3 40 3B C6 73 45 8B 94 24 ?? 00 00 00 8B CE 2B C8 89 0A 8D 51 0B }
	condition:
		$pattern
}

rule RsaRef2_RsaPrivateEncrypt
{	meta:
		author = "Maxx"
		description = "RsaRef2 RsaPrivateEncrypt"
	strings:
		$pattern = { 8B 44 24 14 8B 54 24 10 81 EC 80 00 00 00 8D 4A 0B 56 8B 30 83 C6 07 C1 EE 03 3B CE 76 0D B8 06 04 00 00 5E 81 C4 80 00 00 00 C3 8B CE B8 02 00 00 00 2B CA C6 44 24 04 00 49 C6 44 24 05 01 3B C8 76 23 53 55 8D 69 FE 57 8B CD 83 C8 FF 8B D9 8D 7C 24 12 C1 E9 02 F3 AB 8B CB 83 E1 03 F3 AA 8D 45 02 5F 5D 5B 52 8B 94 24 94 00 00 00 C6 44 04 08 00 8D 44 04 09 52 50 E8 ?? ?? ?? ?? 8B 8C 24 A4 00 00 00 8B 84 24 98 00 00 00 51 8B 8C 24 98 00 00 00 8D 54 24 14 56 52 50 51 E8 }
	condition:
		$pattern
}

rule RsaRef2_RsaPublicDecrypt
{	meta:
		author = "Maxx"
		description = "RsaRef2 RsaPublicDecrypt"
	strings:
		$pattern = { 8B 44 24 14 81 EC 84 00 00 00 8B 8C 24 94 00 00 00 56 8B 30 83 C6 07 C1 EE 03 3B CE 76 0D B8 06 04 00 00 5E 81 C4 84 00 00 00 C3 50 8B 84 24 98 00 00 00 51 8D 4C 24 0C 50 8D 54 24 14 51 52 E8 ?? ?? ?? ?? 83 C4 14 85 C0 0F 85 8E 00 00 00 39 74 24 04 74 0D B8 06 04 00 00 5E 81 C4 84 00 00 00 C3 8A 44 24 08 84 C0 75 6E 80 7C 24 09 01 75 67 B8 02 00 00 00 8D 4E FF 3B C8 76 0D B2 FF 38 54 04 08 75 05 40 3B C1 72 F5 8A 4C 04 08 40 84 C9 75 45 8B 94 24 ?? 00 00 00 8B CE 2B C8 89 0A }
	condition:
		$pattern
}

rule RsaRef2_RsaPublicEncrypt
{	meta:
		author = "Maxx"
		description = "RsaRef2 RsaPublicEncrypt"
	strings:
		$pattern = { 8B 44 24 14 81 EC 84 00 00 00 53 8B 9C 24 98 00 00 00 57 8B 38 83 C7 07 8D 4B 0B C1 EF 03 3B CF 76 0E 5F B8 06 04 00 00 5B 81 C4 84 00 00 00 C3 8B D7 55 2B D3 56 BE 02 00 00 00 C6 44 24 14 00 8D 6A FF C6 44 24 15 02 3B EE 76 28 8B 84 24 AC 00 00 00 8D 4C 24 13 50 6A 01 51 E8 ?? ?? ?? ?? 8A 44 24 1F 83 C4 0C 84 C0 74 E1 88 44 34 14 46 3B F5 72 D8 8B 94 24 A0 00 00 00 53 8D 44 34 19 52 50 C6 44 34 20 00 E8 ?? ?? ?? ?? 8B 8C 24 B4 00 00 00 8B 84 24 A8 00 00 00 51 8B 8C 24 A8 00 }
	condition:
		$pattern
}

rule RsaEuro_NN_modInv
{	meta:
		author = "Maxx"
		description = "RsaEuro NN_modInv"
	strings:
		$pattern = { 81 EC A4 04 00 00 53 56 8B B4 24 BC 04 00 00 57 8D 44 24 0C 56 50 E8 ?? ?? ?? ?? 8D 8C 24 1C 01 00 00 BF 01 00 00 00 56 51 89 7C 24 1C E8 ?? ?? ?? ?? 8B 94 24 C8 04 00 00 56 8D 84 24 AC 01 00 00 52 50 E8 ?? ?? ?? ?? 8B 9C 24 D8 04 00 00 56 8D 8C 24 B0 00 00 00 53 51 E8 ?? ?? ?? ?? 8D 94 24 B8 00 00 00 56 52 E8 ?? ?? ?? ?? 83 C4 30 85 C0 0F 85 F8 00 00 00 8D 84 24 ?? 00 00 00 56 50 8D 8C 24 A0 01 00 00 56 8D 94 24 AC 02 00 00 51 8D 84 24 34 03 00 00 52 50 E8 ?? ?? ?? ?? 8D 8C }
	condition:
		$pattern
}

rule RsaEuro_NN_modMult
{	meta:
		author = "Maxx"
		description = "RsaEuro NN_modMult"
	strings:
		$pattern = { 8B 44 24 0C 8B 4C 24 08 81 EC 08 01 00 00 8D 54 24 00 56 8B B4 24 20 01 00 00 56 50 51 52 E8 ?? ?? ?? ?? 8B 84 24 2C 01 00 00 56 8D 0C 36 50 8B 84 24 28 01 00 00 8D 54 24 1C 51 52 50 E8 ?? ?? ?? ?? 83 C4 24 5E 81 C4 08 01 00 00 C3 }
	condition:
		$pattern
}

rule Miracl_Big_constructor
{	meta:
		author = "Maxx"
		description = "Miracl Big constructor"
	strings:
		$pattern = { 56 8B F1 6A 00 E8 ?? ?? ?? ?? 83 C4 04 89 06 8B C6 5E C3 }
	condition:
		$pattern
}

rule Miracl_mirvar
{	meta:
		author = "Maxx"
		description = "Miracl mirvar"
	strings:
		$pattern1 = { 56 E8 ?? ?? ?? ?? 8B 88 18 02 00 00 85 C9 74 04 33 C0 5E C3 8B 88 8C 00 00 00 85 C9 75 0E 6A 12 E8 ?? ?? ?? ?? 83 C4 04 33 C0 5E C3 8B 80 38 02 00 00 6A 01 50 E8 ?? ?? ?? ?? 8B F0 83 C4 08 85 F6 75 02 5E C3 8D 46 04 8B C8 8B D0 83 E1 03 2B D1 83 C2 08 89 10 8B 44 24 08 85 C0 74 0A 56 50 E8 ?? ?? ?? ?? 83 C4 08 8B C6 5E C3 }
		$pattern2 = { 56 57 E8 ?? ?? ?? ?? 8B F0 8B 86 2C 02 00 00 85 C0 74 05 5F 33 C0 5E C3 8B 56 1C 42 8B C2 89 56 1C 83 F8 18 7D 17 C7 44 86 20 17 00 00 00 8B 86 40 02 00 00 85 C0 74 05 E8 ?? ?? ?? ?? 8B 86 8C 00 00 00 85 C0 75 16 6A 12 E8 ?? ?? ?? ?? 8B 46 1C 83 C4 04 48 89 46 1C 5F 33 C0 5E C3 8B 46 18 6A 01 8D 0C 85 0C 00 00 00 51 E8 ?? ?? ?? ?? 8B F8 83 C4 08 85 FF 75 0C 8B 46 1C 5F 48 89 46 1C 33 C0 5E C3 8D 47 04 8B D0 8B C8 83 E2 03 2B CA 83 C1 08 89 08 8B 44 24 0C 85 C0 74 0A 57 50 E8 }
		$pattern3 = { 56 57 E8 ?? ?? ?? ?? 8B F0 8B 86 18 02 00 00 85 C0 74 05 5F 33 C0 5E C3 8B 56 1C 42 8B C2 89 56 1C 83 F8 18 7D 17 C7 44 86 20 17 00 00 00 8B 86 2C 02 00 00 85 C0 74 05 E8 ?? ?? ?? ?? 8B 86 8C 00 00 00 85 C0 75 16 6A 12 E8 ?? ?? ?? ?? 8B 46 1C 83 C4 04 48 89 46 1C 5F 33 C0 5E C3 8B 86 A4 02 00 00 6A 01 50 E8 ?? ?? ?? ?? 8B F8 83 C4 08 85 FF 75 0C 8B 46 1C 5F 48 89 46 1C 33 C0 5E C3 8D 47 04 8B C8 8B D0 83 E1 03 2B D1 83 C2 08 89 10 8B 44 24 0C 85 C0 74 0A 57 50 E8 }
	condition:
		any of them
}

rule Miracl_mirsys_init
{	meta:
		author = "Maxx"
		description = "Miracl mirsys init"
	strings:
		$pattern = { 53 55 57 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 DB A3 ?? ?? ?? ?? 3B C3 75 06 5F 5D 33 C0 5B C3 89 58 1C A1 ?? ?? ?? ?? BD 01 00 00 00 89 58 20 A1 ?? ?? ?? ?? 8B 50 1C 42 89 50 1C A1 ?? ?? ?? ?? 8B 48 1C C7 44 88 20 1D 00 00 00 8B 15 ?? ?? ?? ?? 89 9A 14 02 00 00 A1 ?? ?? ?? ?? 89 98 70 01 00 00 8B 0D ?? ?? ?? ?? 89 99 78 01 00 00 8B 15 ?? ?? ?? ?? 89 9A 98 01 00 00 A1 ?? ?? ?? ?? 89 58 14 8B 44 24 14 3B C5 0F 84 6C 05 00 00 3D 00 00 00 80 0F 87 61 05 00 00 50 E8 }
	condition:
		$pattern
}

rule x509_public_key_infrastructure_cert
{
  	meta:
		author = "Storm Shadow"
		description = "X.509 PKI Certificate"
		ext = "crt"
	strings: $a = {30 82 ?? ?? 30 82 ?? ??}
  	condition: $a
}

rule pkcs8_private_key_information_syntax_standard
{
	meta:
		desc = "Found PKCS #8: Private-Key"
		ext = "key"
	strings: $a = {30 82 ?? ?? 02 01 00}
	condition: $a
}
