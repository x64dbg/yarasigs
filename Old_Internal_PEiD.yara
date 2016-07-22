import "pe"


rule armd60a
{
	meta:
		author = "PEiD"
		description = "Armadillo 1.60a -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 55 8B EC 6A FF 68 98 71 ?? ?? 68 48 2D ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 }
	condition:
		$a0
}

/*
Armadillo 1.71 -> Silicon Realms Toolworks
Armadillo 1.72 - 1.73 -> Silicon Realms Toolworks
Armadillo 1.75a -> Silicon Realms Toolworks
Armadillo 1.76 -> Silicon Realms Toolworks
Armadillo 1.77 -> Silicon Realms Toolworks
Armadillo 1.77.1 -> Silicon Realms Toolworks
Armadillo 1.80 -> Silicon Realms Toolworks
Armadillo 1.80 beta1 -> Silicon Realms Toolworks
Armadillo 1.80 beta2 -> Silicon Realms Toolworks
Armadillo 1.80 beta3 -> Silicon Realms Toolworks
Armadillo 1.80 beta4 -> Silicon Realms Toolworks
Armadillo 1.81 -> Silicon Realms Toolworks
Armadillo 1.82 - 1.83 beta1-> Silicon Realms Toolworks
Armadillo 1.83 beta2 -> Silicon Realms Toolworks
Armadillo 1.90 -> Silicon Realms Toolworks
Armadillo 1.90 beta1 -> Silicon Realms Toolworks
Armadillo 1.90 beta2 -> Silicon Realms Toolworks
Armadillo 1.90 beta3 -> Silicon Realms Toolworks
Armadillo 1.90 beta4 -> Silicon Realms Toolworks
Armadillo 1.91a -> Silicon Realms Toolworks
Armadillo 1.91c -> Silicon Realms Toolworks
Armadillo 2.00 beta1 -> Silicon Realms Toolworks
Armadillo 2.00 beta3 -> Silicon Realms Toolworks
Armadillo 2.00a -> Silicon Realms Toolworks
Armadillo 2.01 -> Silicon Realms Toolworks
Armadillo 2.10 -> Silicon Realms Toolworks
Armadillo 2.10 beta2 -> Silicon Realms Toolworks
Armadillo 2.10 beta3 -> Silicon Realms Toolworks
Armadillo 2.20 -> Silicon Realms Toolworks
Armadillo 1.xx - 2.xx -> Silicon Realms Toolworks
*/
rule armd71
{
	meta:
		author = "PEiD"
		description = "Armadillo 1.71 - 2.6x -> Silicon Realms Toolworks"
		group = "104"
		function = "5"
	strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 }
	condition:
		$a0
}

rule armd84
{
	meta:
		author = "PEiD"
		description = "Armadillo 1.84 -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 55 8B EC 6A FF 68 E8 C1 ?? ?? 68 F4 86 ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 }
	condition:
		$a0
}

rule armd250b
{
	meta:
		author = "PEiD"
		description = "Armadillo 2.50 beta -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 55 8B EC 6A FF 68 98 ?? ?? ?? 68 10 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 }
	condition:
		$a0
}

rule armd250
{
	meta:
		author = "PEiD"
		description = "Armadillo 2.50 -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 55 8B EC 6A FF 68 B8 ?? ?? ?? 68 F8 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 20 ?? ?? ?? 33 D2 8A D4 89 15 D0 }
	condition:
		$a0
}

rule armd251
{
	meta:
		author = "PEiD"
		description = "Armadillo 2.51 -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 55 8B EC 6A FF 68 B8 ?? ?? ?? 68 D0 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 20 }
	condition:
		$a0
}

rule armd252b2
{
	meta:
		author = "PEiD"
		description = "Armadillo 2.52 beta2 -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 55 8B EC 6A FF 68 B0 ?? ?? ?? 68 60 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 24 }
	condition:
		$a0
}

rule armd252
{
	meta:
		author = "PEiD"
		description = "Armadillo 2.52 -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 55 8B EC 6A FF 68 E0 ?? ?? ?? 68 D4 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 38 }
	condition:
		$a0
}

rule armd253b3
{
	meta:
		author = "PEiD"
		description = "Armadillo 2.53 beta3 -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 55 8B EC 6A FF 68 D8 ?? ?? ?? 68 14 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 }
	condition:
		$a0
}

rule armd253
{
	meta:
		author = "PEiD"
		description = "Armadillo 2.53 -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 55 8B EC 6A FF 68 40 ?? ?? ?? 68 54 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 EC }
	condition:
		$a0
}

rule armd26b1
{
	meta:
		author = "PEiD"
		description = "Armadillo 2.60 beta1 -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 55 8B EC 6A FF 68 50 ?? ?? ?? 68 74 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 FC }
	condition:
		$a0
}

rule armd26b2
{
	meta:
		author = "PEiD"
		description = "Armadillo 2.60 beta2 -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 55 8B EC 6A FF 68 90 ?? ?? ?? 68 24 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 60 ?? ?? ?? 33 D2 8A D4 89 15 3C }
	condition:
		$a0
}

rule armd26
{
	meta:
		author = "PEiD"
		description = "Armadillo 2.60 -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 55 8B EC 6A FF 68 D0 ?? ?? ?? 68 34 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 68 ?? ?? ?? 33 D2 8A D4 89 15 84 }
	condition:
		$a0
}

rule armd26a
{
	meta:
		author = "PEiD"
		description = "Armadillo 2.60a -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 94 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 6C ?? ?? ?? 33 D2 8A D4 89 15 B4 }
	condition:
		$a0
}

rule armd26c
{
	meta:
		author = "PEiD"
		description = "Armadillo 2.60c -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 55 8B EC 6A FF 68 40 ?? ?? ?? 68 F4 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 6C ?? ?? ?? 33 D2 8A D4 89 15 F4 }
	condition:
		$a0
}

rule armd261
{
	meta:
		author = "PEiD"
		description = "Armadillo 2.61 -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 55 8B EC 6A FF 68 28 ?? ?? ?? 68 E4 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 6C ?? ?? ?? 33 D2 8A D4 89 15 0C }
	condition:
		$a0
}

rule armd265b1
{
	meta:
		author = "PEiD"
		description = "Armadillo 2.65 beta1 -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 55 8B EC 6A FF 68 38 ?? ?? ?? 68 40 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 28 ?? ?? ?? 33 D2 8A D4 89 15 F4 }
	condition:
		$a0
}

rule armd275a
{
	meta:
		author = "PEiD"
		description = "Armadillo 2.75a -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 55 8B EC 6A FF 68 68 ?? ?? ?? 68 D0 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 28 ?? ?? ?? 33 D2 8A D4 89 15 24 }
	condition:
		$a0
}

rule armd285
{
	meta:
		author = "PEiD"
		description = "Armadillo 2.85 -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 55 8B EC 6A FF 68 68 ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 28 ?? ?? ?? 33 D2 8A D4 89 15 24 }
	condition:
		$a0
}

rule armd25_cm2
{
	meta:
		author = "PEiD"
		description = "Armadillo 2.5x - 2.6x [CopyMem II] -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 6A ?? 8B B5 ?? ?? ?? ?? C1 E6 04 8B 85 ?? ?? ?? ?? 25 07 ?? ?? 80 79 05 48 83 C8 F8 40 33 C9 8A 88 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 81 E2 07 ?? ?? 80 79 05 4A 83 CA F8 42 33 C0 8A 82 }
	condition:
		$a0
}

rule armd300
{
	meta:
		author = "PEiD"
		description = "Armadillo 3.00 -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 60 33 C9 }
	condition:
		$a0
}

rule armd300a
{
	meta:
		author = "PEiD"
		description = "Armadillo 3.00a - 3.61 -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB }
	condition:
		$a0
}

rule armd30x
{
	meta:
		author = "PEiD"
		description = "Armadillo 3.xx -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 }
	condition:
		$a0
}

rule armd350b1
{
	meta:
		author = "PEiD"
		description = "Armadillo 3.50b1 -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 F3 D8 04 24 9C 51 33 C9 75 02 F3 D8 04 24 EB 1A EB 33 C9 75 18 59 F3 D8 04 24 7A 0C 70 0E EB 0D E8 72 0E 79 EE }
	condition:
		$a0
}

rule arma36x
{
	meta:
		author = "PEiD"
		description = "Armadillo 3.6x -> Silicon Realms Toolworks"
		group = "444"
		function = "4"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 60 33 C9 75 02 EB 15 ?? 33 C9 75 18 7A 0C 70 0E EB 0D ?? 72 0E 79 F1 ?? ?? ?? 79 09 74 F0 ?? 87 DB 7A F0 ?? ?? 61 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 60 9C 33 C0 E8 09 00 00 00 E8 E8 23 00 00 00 7A 23 ?? 8B 04 24 EB 03 7A 29 ?? C6 00 90 C3 ?? 70 F0 87 D2 71 07 ?? ?? 40 8B DB 7A 11 EB 08 ?? EB F7 EB C3 ?? 7A E9 70 DA 7B D1 71 F3 ?? 7B F3 71 D6 ?? 9D 61 83 ED 06 33 FF 47 60 33 C9 75 02 EB 15 ?? 33 C9 75 18 7A 0C 70 0E EB 0D ?? 72 0E 79 F1 ?? ?? ?? 79 09 74 F0 EB 87 ?? 7A F0 ?? ?? 61 8B 9C BD AB 76 }
	condition:
		$a0
}

rule arma37x
{
	meta:
		author = "PEiD"
		description = "Armadillo 3.7x -> Silicon Realms Toolworks"
		group = "444"
		function = "4"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 60 33 C9 75 02 EB 15 ?? 33 C9 75 18 7A 0C 70 0E EB 0D ?? 72 0E 79 F1 ?? ?? ?? 79 09 74 F0 ?? 87 DB 7A F0 ?? ?? 61 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 60 9C 33 C0 E8 09 00 00 00 E8 E8 23 00 00 00 7A 23 ?? 8B 04 24 EB 03 7A 29 ?? C6 00 90 C3 ?? 70 F0 87 D2 71 07 ?? ?? 40 8B DB 7A 11 EB 08 ?? EB F7 EB C3 ?? 7A E9 70 DA 7B D1 71 F3 ?? 7B F3 71 D6 ?? 9D 61 83 ED 06 B8 3B 01 00 00 03 C5 33 DB 81 C3 01 01 01 01 31 18 81 38 78 54 00 00 74 04 31 18 EB EC }
	condition:
		$a0
}

rule armd378
{
	meta:
		author = "PEiD"
		description = "Armadillo 3.78 - 4.xx -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 50 51 0F CA F7 }
	condition:
		$a0
}

rule armd25
{
	meta:
		author = "PEiD"
		description = "Armadillo 2.5x - 2.6x -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 6A ?? 8B 4D 08 51 E8 AE ?? ?? ?? 83 C4 08 25 FF ?? ?? ?? 85 C0 75 07 32 C0 E9 97 }
	condition:
		$a0
}

/*
name     = WARNING -> VIRUS -> W32@NimDA_mm
hardcore = 0
oep      = 0x74b3
group    = 800
*/
rule ms_vc6_dll
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 6.0 DLL"
		group = "15"
		function = "17"
	strings:
		$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 }
	condition:
		$a0 at pe.entry_point
}

rule klez
{
	meta:
		author = "PEiD"
		description = "WARNING -> VIRUS -> I-Worm KLEZ"
		group = "800"
		function = "13"
	strings:
		$a0 = { 55 8B EC 6A FF 68 40 D2 40 ?? 68 04 AC 40 ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 BC D0 }
	condition:
		$a0
}

rule sobiga
{
	meta:
		author = "PEiD"
		description = "WARNING -> VIRUS -> W32@Sobig.A_mm"
		group = "800"
		function = "21"
	strings:
		$a0 = { E9 25 E4 FF FF ?? ?? ?? 1F 9F 84 10 1E CC 01 }
	condition:
		$a0
}

rule sobige
{
	meta:
		author = "PEiD"
		description = "WARNING -> VIRUS -> W32@Sobig.E_mm"
		group = "800"
		function = "22"
	strings:
		$a0 = { E9 25 E4 FF FF ?? ?? ?? CF 0E 96 3E 1E 5C 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? 3E 5C 02 ?? 2E 5C 02 ?? 26 5C 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? 4B 5C 02 ?? 36 5C 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 56 5C 02 ?? ?? ?? ?? ?? 69 5C 02 ?? ?? ?? ?? ?? 56 5C 02 ?? ?? ?? ?? ?? 69 5C 02 ?? ?? ?? ?? ?? 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C ?? 75 73 65 72 33 32 2E 64 6C 6C ?? ?? ?? 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 ?? ?? ?? 4D 65 73 73 61 67 65 42 6F 78 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 08 ?? ?? ?? ?? ?? BC 5D 02 ?? E2 5D 02 ?? F9 5D 02 ?? 3C 5E 02 ?? 57 5E 02 ?? 7C 5E 02 ?? 91 5E 02 ?? 0E 5F 02 }
	condition:
		$a0 at pe.entry_point
}

rule sobigf
{
	meta:
		author = "PEiD"
		description = "WARNING -> VIRUS -> W32@Sobig.F_mm"
		group = "800"
		function = "23"
	strings:
		$a0 = { E9 25 E4 FF FF ?? ?? ?? 0B ?? B0 ED 1E EC 01 }
	condition:
		$a0
}

rule borland_cpp
{
	meta:
		author = "PEiD"
		description = "Borland C++"
		group = "10"
		function = "0"
	strings:
		$a0 = { A1 ?? ?? ?? ?? C1 E0 02 A3 ?? ?? ?? ?? 57 51 33 C0 BF ?? ?? ?? ?? B9 ?? ?? ?? ?? 3B CF 76 05 2B CF FC F3 AA 59 5F }
	condition:
		$a0 at pe.entry_point
}

/*
[bcpp_dll1]

A1 ?? ?? ?? ?? C1 E0 02 A3

name     = Borland C++ DLL Method 1
hardcore = 0
group    = 10
*/
rule bcpp2
{
	meta:
		author = "PEiD"
		description = "Borland C++ 1999"
		group = "10"
		function = "0"
	strings:
		$a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 ?? ?? ?? ?? A1 ?? ?? ?? ?? C1 E0 02 A3 ?? ?? ?? ?? 52 }
	condition:
		$a0 at pe.entry_point
}

rule bcpp_dll2
{
	meta:
		author = "PEiD"
		description = "Borland C++ DLL Method 2"
		group = "10"
		function = "0"
	strings:
		$a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 }
	condition:
		$a0
}

rule bcpp_dll3
{
	meta:
		author = "PEiD"
		description = "Borland C++ DLL Method 3"
		group = "10"
		function = "0"
	strings:
		$a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 ?? ?? ?? ?? A1 ?? ?? ?? ?? C1 E0 02 A3 ?? ?? ?? ?? 8B }
	condition:
		$a0 at pe.entry_point
}

rule bdelphi_dll
{
	meta:
		author = "PEiD"
		description = "Borland Delphi DLL"
		group = "11"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 ?? ?? FF FF E8 ?? ?? FF FF 8D 40 00 }
	condition:
		$a0
}

rule borland_delphi2
{
	meta:
		author = "PEiD"
		description = "Borland Delphi 2.0"
		group = "11"
		function = "0"
	strings:
		$a0 = { E8 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 0A ?? ?? ?? B8 ?? ?? ?? ?? C3 }
	condition:
		$a0 at pe.entry_point
}

rule borland_delphi3
{
	meta:
		author = "PEiD"
		description = "Borland Delphi 3.0"
		group = "11"
		function = "0"
	strings:
		$a0 = { 50 6A ?? E8 ?? ?? FF FF BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 55 8B EC 33 C0 }
	condition:
		$a0 at pe.entry_point
}

rule borland_delphi5
{
	meta:
		author = "PEiD"
		description = "Borland Delphi 4.0 - 5.0"
		group = "11"
		function = "0"
	strings:
		$a0 = { 50 6A ?? E8 ?? ?? FF FF BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 C7 42 08 ?? ?? ?? ?? C7 42 0C ?? ?? ?? ?? E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 }
	condition:
		$a0 at pe.entry_point
}

rule borland_delphi6
{
	meta:
		author = "PEiD"
		description = "Borland Delphi 6.0 - 7.0 / 2005 - 2007"
		group = "11"
		function = "0"
	strings:
		$a0 = { 53 8B D8 33 C0 A3 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? FF A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? E8 }
	condition:
		$a0 at pe.entry_point
}

rule borland_delphi_dll
{
	meta:
		author = "PEiD"
		description = "Borland Delphi DLL"
		group = "11"
		function = "0"
	strings:
		$a0 = { BA ?? ?? ?? ?? 83 7D 0C 01 75 ?? 50 52 C6 05 ?? ?? ?? ?? ?? 8B 4D 08 89 0D ?? ?? ?? ?? 89 4A 04 }
	condition:
		$a0 at pe.entry_point
}

rule borland_delphi_setup
{
	meta:
		author = "PEiD"
		description = "Borland Delphi Setup Module"
		group = "11"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 E8 }
	condition:
		$a0 at pe.entry_point
}

rule borland_delphi_5_KOL_MCK
{
	meta:
		author = "PEiD"
		description = "Borland Delphi 5.0 KOL/MCK"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 8B EC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? 00 00 00 }
	condition:
		$a0
}

rule borland_delphi_6_kol
{
	meta:
		author = "PEiD"
		description = "Borland Delphi 6.0 KOL"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 ?? ?? 40 00 E8 ?? ?? FF FF A1 ?? 72 40 00 33 D2 E8 ?? ?? FF FF A1 ?? 72 40 00 8B 00 83 C0 14 E8 ?? ?? FF FF E8 ?? ?? FF FF }
	condition:
		$a0
}

rule borland_delphi_5_kol
{
	meta:
		author = "PEiD"
		description = "Borland Delphi 5.0 KOL"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 ?? ?? 40 00 E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF 8B C0 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$a0
}

rule Borland_delphi_6
{
	meta:
		author = "PEiD"
		description = "Borland Delphi 6.0"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 ?? ?? 45 00 E8 ?? ?? ?? FF A1 ?? ?? 45 00 8B 00 E8 ?? ?? FF FF 8B 0D }
	condition:
		$a0
}

rule devcpp4992
{
	meta:
		author = "PEiD"
		description = "Dev-C++ 4.9.9.2 -> Bloodshed Software"
		group = "999"
		function = "0"
	strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 ?? ?? ?? 00 E8 C8 FE FF FF 90 8D B4 26 00 00 00 00 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 ?? ?? ?? 00 E8 A8 FE FF FF 90 8D B4 26 00 00 00 00 55 8B 0D ?? ?? ?? 00 89 E5 5D FF E1 8D 74 26 00 55 8B 0D ?? ?? ?? 00 89 E5 5D FF E1 90 90 90 90 55 89 E5 5D E9 ?? ?? 00 00 90 90 90 90 90 90 90 }
	condition:
		$a0
}

rule freebasic014
{
	meta:
		author = "PEiD"
		description = "FreeBasic 0.14"
		group = "999"
		function = "0"
	strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? ?? 00 E8 ?? FF FF FF 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 89 E5 83 EC 08 8B 45 08 89 04 24 FF 15 ?? ?? ?? 00 89 EC 5D C3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 89 E5 }
	condition:
		$a0
}

rule freepascal
{
	meta:
		author = "PEiD"
		description = "FreePascal 2.0.0 -> B?rczi G?bor, Pierre Muller & Peter Vreman"
		group = "999"
		function = "0"
	strings:
		$a0 = { C6 05 00 80 40 00 01 E8 74 00 00 00 C6 05 00 80 40 00 00 E8 68 00 00 00 50 E8 00 00 00 00 FF 25 D8 A1 40 00 90 90 90 90 90 90 90 90 90 90 90 90 55 89 E5 83 EC 04 89 5D FC E8 92 00 00 00 E8 ED 00 00 00 89 C3 B9 ?? 70 40 00 89 DA B8 00 00 00 00 E8 0A 01 00 00 E8 C5 01 00 00 89 D8 E8 3E 02 00 00 E8 B9 01 00 00 E8 54 02 00 00 8B 5D FC C9 C3 8D 76 00 00 00 00 00 00 00 00 00 00 00 00 00 55 89 E5 C6 05 10 80 40 00 00 E8 D1 03 00 00 6A 00 64 FF 35 00 00 00 00 89 E0 A3 ?? 70 40 00 55 31 ED 89 E0 A3 20 80 40 00 66 8C D5 89 2D 30 80 40 00 E8 B9 03 00 00 31 ED E8 72 FF FF FF 5D E8 BC 03 00 00 C9 C3 00 00 00 00 00 00 00 00 00 00 55 89 E5 83 EC 08 E8 15 04 00 00 A1 ?? 70 40 00 89 45 F8 B8 01 00 00 00 89 45 FC 3B 45 F8 7F 2A FF 4D FC 90 FF 45 FC 8B 45 FC 83 3C C5 ?? 70 40 00 00 74 09 8B 04 C5 ?? 70 40 }
	condition:
		$a0
}

rule lcc_win32
{
	meta:
		author = "PEiD"
		description = "LCC Win32 1.x -> Jacob Navia"
		group = "12"
		function = "0"
	strings:
		$a0 = { 64 A1 ?? ?? ?? ?? 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 ?? 50 }
	condition:
		$a0 at pe.entry_point
}

rule lcc_dll
{
	meta:
		author = "PEiD"
		description = "LCC Win32 DLL -> Jacob Navia"
		group = "12"
		function = "0"
	strings:
		$a0 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 ?? ?? ?? FF 75 10 FF 75 0C FF 75 08 A1 }
	condition:
		$a0 at pe.entry_point
}

rule reflexive_arcade_wrapper
{
	meta:
		author = "PEiD"
		description = "Reflexive Arcade Wrapper"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 8B EC 6A FF 68 98 68 42 00 68 14 FA 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 F8 50 42 00 33 D2 8A D4 89 15 3C E8 42 00 8B C8 81 E1 FF 00 00 00 89 0D 38 E8 42 00 C1 E1 08 03 CA 89 0D 34 E8 42 00 C1 E8 10 A3 30 E8 42 00 33 F6 56 E8 58 43 00 00 59 85 C0 75 08 6A 1C E8 B0 00 00 00 59 89 75 FC E8 23 40 00 00 FF 15 18 51 42 00 A3 44 FE 42 00 E8 E1 3E 00 00 A3 78 E8 42 00 E8 8A 3C 00 00 E8 CC 3B 00 00 E8 3E F5 FF FF 89 75 D0 8D 45 A4 50 FF 15 14 51 42 00 E8 5D 3B 00 00 89 45 9C F6 45 D0 01 74 06 0F B7 45 D4 EB 03 6A 0A 58 50 FF 75 9C 56 56 FF 15 10 51 42 00 50 E8 0D 6E FE FF 89 45 A0 50 E8 2C F5 FF FF 8B 45 EC 8B 08 8B 09 89 4D 98 50 51 E8 9B 39 00 00 59 59 C3 8B 65 E8 FF 75 98 E8 1E F5 FF FF 83 3D 80 E8 42 00 01 75 05 E8 F3 43 00 00 FF 74 24 04 E8 23 44 00 00 68 FF 00 00 00 FF 15 B0 B8 42 00 59 59 C3 83 3D 80 E8 42 00 01 75 05 E8 CE 43 00 00 FF 74 24 04 E8 FE 43 00 00 59 68 FF 00 00 00 FF 15 04 51 42 00 C3 55 8B EC 81 EC F8 00 00 00 53 56 8B 75 0C 57 83 FE 02 }
	condition:
		$a0
}

rule ibasic202
{
	meta:
		author = "PEiD"
		description = "IBasic 2.02B -> Pyxia Development"
		group = "12"
		function = "0"
	strings:
		$a0 = { 55 8B EC 6A FF 68 D0 10 46 00 68 58 9F 43 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 C4 A8 53 56 57 89 65 E8 FF 15 D8 2B 47 00 33 D2 8A D4 89 15 C4 FD 46 00 8B C8 81 E1 FF 00 00 00 89 0D C0 FD 46 00 C1 E1 08 03 CA 89 0D BC FD 46 00 C1 E8 10 A3 B8 FD 46 00 E8 54 25 00 00 85 C0 }
	condition:
		$a0
}

/*
name     = InstallShield 2000 stub
hardcore = 0
oep      = 0xdfe0
group    = 301
*/
rule ms_vc5
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 5.0"
		group = "15"
		function = "16"
	strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 C4 ?? 53 56 57 }
	condition:
		$a0 at pe.entry_point
}

rule ms_vc4
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 4.x"
		group = "15"
		function = "0"
	strings:
		$a0 = { 64 A1 ?? ?? ?? ?? 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 }
	condition:
		$a0 at pe.entry_point
}

rule ms_vc6
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 6.0"
		group = "15"
		function = "24"
	strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 }
	condition:
		$a0 at pe.entry_point
}

rule ms_vc620
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 6.20"
		group = "15"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 EC 50 53 56 57 BE ?? ?? ?? ?? 8D 7D F4 A5 A5 66 A5 8B }
	condition:
		$a0 at pe.entry_point
}

rule ms_vc7
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 7.0"
		group = "15"
		function = "25"
	strings:
		$a0 = { 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 8B C7 E8 ?? ?? ?? ?? 89 65 ?? 8B F4 89 3E 56 FF 15 ?? ?? ?? ?? 8B 4E ?? 89 0D ?? ?? ?? ?? 8B 46 ?? A3 }
	condition:
		$a0 at pe.entry_point
}

rule ms_vc72
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 7.0 Method2"
		group = "15"
		function = "25"
	strings:
		$a0 = { 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? 00 33 DB }
	condition:
		$a0
}

rule ms_vc8
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 8.0"
		group = "999"
		function = "0"
	strings:
		$a0 = { 6A 14 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BB 94 00 00 00 53 6A 00 8B ?? ?? ?? ?? ?? FF D7 50 FF ?? ?? ?? ?? ?? 8B F0 85 F6 75 0A 6A 12 E8 ?? ?? ?? ?? 59 EB 18 89 1E 56 FF ?? ?? ?? ?? ?? 56 85 C0 75 14 50 FF D7 50 FF ?? ?? ?? ?? ?? B8 }
	condition:
		$a0 at pe.entry_point
}

rule ms_vc_h
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++"
		group = "15"
		function = "0"
	strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 }
	condition:
		$a0 at pe.entry_point
}

rule ms_vc8_h2
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 8.0 DLL"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { 8B FF 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 0F 84 ?? ?? 00 00 83 FE 01 }
	condition:
		$a0 at pe.entry_point
}

rule ms_vc_net
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C# / Basic .NET"
		group = "115"
		function = "0"
	strings:
		$a0 = { FF 25 00 20 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$a0
}

rule ms_vc7_dll
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 7.0 DLL Method 1"
		group = "15"
		function = "0"
	strings:
		$a0 = { 55 8D 6C ?? ?? 81 EC ?? ?? ?? ?? 8B 45 ?? 83 F8 01 56 0F 84 ?? ?? ?? ?? 85 C0 0F 84 }
	condition:
		$a0 at pe.entry_point
}

rule ms_vc7_dll2
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 7.0 DLL Method 2"
		group = "15"
		function = "0"
	strings:
		$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 ?? ?? 83 }
	condition:
		$a0 at pe.entry_point
}

rule ms_vc7_dll3
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 7.0 DLL Method 3"
		group = "15"
		function = "0"
	strings:
		$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C }
	condition:
		$a0
}

rule ms_vc_dll1
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ DLL Method 1"
		group = "15"
		function = "0"
	strings:
		$a0 = { 53 55 56 8B 74 24 14 85 F6 57 B8 01 }
	condition:
		$a0 at pe.entry_point
}

rule ms_vc_dll2
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ DLL Method 2"
		group = "15"
		function = "0"
	strings:
		$a0 = { 53 56 57 BB 01 ?? ?? ?? 8B ?? 24 14 }
	condition:
		$a0 at pe.entry_point
}

rule ms_vc_dll3
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ DLL Method 3"
		group = "15"
		function = "0"
	strings:
		$a0 = { 53 B8 01 ?? ?? ?? 8B 5C 24 0C 56 57 85 DB 55 75 12 83 3D ?? ?? ?? ?? ?? 75 09 33 C0 }
	condition:
		$a0 at pe.entry_point
}

rule ms_vc_dll4
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ DLL Method 4"
		group = "15"
		function = "0"
	strings:
		$a0 = { 55 8B EC 56 57 BF 01 ?? ?? ?? 8B 75 0C }
	condition:
		$a0 at pe.entry_point
}

rule ms_vb_dll
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual Basic 6.0 DLL"
		group = "16"
		function = "0"
	strings:
		$a0 = { 5A 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 52 E9 ?? ?? FF }
	condition:
		$a0 at pe.entry_point
}

rule msvc_prvt1
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ Private Version 1"
		group = "15"
		function = "0"
	strings:
		$a0 = { 8B 44 24 08 83 ?? ?? 74 }
	condition:
		$a0
}

rule msvc_prvt2
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ Private Version 2"
		group = "15"
		function = "0"
	strings:
		$a0 = { 8B 44 24 08 56 83 E8 ?? 74 ?? 48 75 }
	condition:
		$a0
}

rule watcom_c
{
	meta:
		author = "PEiD"
		description = "Watcom C/C++ EXE"
		group = "17"
		function = "0"
	strings:
		$a0 = { E9 ?? ?? ?? ?? ?? ?? ?? ?? 57 41 }
	condition:
		$a0
}

rule watcom_c_dll
{
	meta:
		author = "PEiD"
		description = "Watcom C/C++ DLL"
		group = "17"
		function = "0"
	strings:
		$a0 = { 53 56 57 55 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 83 FF 03 0F 87 }
	condition:
		$a0 at pe.entry_point
}

rule watcom_c_h
{
	meta:
		author = "PEiD"
		description = "Watcom C/C++ EXE Heuristic Mode"
		group = "17"
		function = "0"
	strings:
		$a0 = { 53 51 52 55 89 E5 83 EC 08 B8 01 ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C0 03 }
	condition:
		$a0 at pe.entry_point
}

rule packman0001
{
	meta:
		author = "PEiD"
		description = "Packman 0.0.0.1 -> Bubbasoft"
		group = "444"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 58 8D A8 ?? FE FF FF 8D 98 ?? ?? ?? FF 8D B0 74 01 00 00 8D 4E F6 48 C6 40 FB E9 8D 93 ?? ?? ?? 00 2B D0 89 50 FC 8D 93 54 01 00 00 E9 9A 00 00 00 83 C2 04 03 FB 51 D1 C7 D1 EF 0F 83 84 00 00 00 53 55 52 B2 80 8B D9 }
	condition:
		$a0
}

rule passlock2000
{
	meta:
		author = "PEiD"
		description = "PassLock 2000 1.0 (Eng) -> Moonlight-Software"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 8B EC 53 56 57 BB 00 50 40 00 66 2E F7 05 34 20 40 00 04 00 0F 85 98 00 00 00 E8 1F 01 00 00 C7 43 60 01 00 00 00 8D 83 E4 01 00 00 50 FF 15 F0 61 40 00 83 EC 44 C7 04 24 44 00 00 00 C7 44 24 2C 00 00 00 00 54 FF 15 E8 61 40 00 B8 0A 00 00 00 F7 44 24 2C 01 00 00 00 74 05 0F B7 44 24 30 83 C4 44 89 43 56 FF 15 D0 61 40 00 E8 9E 00 00 00 89 43 4C FF 15 D4 61 40 00 89 43 48 6A 00 FF 15 E4 61 40 00 89 43 5C E8 F9 00 00 00 E8 AA 00 00 00 B8 FF 00 00 00 72 0D 53 E8 96 00 00 00 5B FF 4B 10 FF 4B 18 5F 5E 5B 5D 50 FF 15 C8 61 40 00 C3 83 7D 0C 01 75 3F E8 81 00 00 00 8D 83 E4 01 00 00 50 FF 15 F0 61 40 00 FF 15 D0 61 40 00 E8 3A 00 00 00 89 43 4C FF 15 D4 61 40 00 89 43 48 8B 45 08 89 43 5C E8 9A 00 00 00 E8 4B 00 00 00 72 11 66 FF 43 5A 8B 45 0C 89 43 60 53 }
	condition:
		$a0
}

rule pe123_412
{
	meta:
		author = "PEiD"
		description = "Pe123 2006.4.12"
		group = "444"
		function = "0"
	strings:
		$a0 = { 8B C0 60 9C E8 01 00 00 00 C3 53 E8 72 00 00 00 50 E8 1C 03 00 00 8B D8 FF D3 5B C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 55 8B EC 60 8B 4D 10 8B 7D 0C 8B 75 08 F3 A4 61 5D C2 0C 00 E8 00 00 00 00 58 83 E8 05 C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 E8 00 00 00 00 58 C1 E8 0C C1 E0 0C 66 81 38 4D 5A 74 0C 2D 00 10 00 00 66 81 38 4D 5A 75 F4 C3 E8 00 00 00 00 58 83 E8 05 C3 8B C0 55 8B EC 81 C4 4C FE FF FF 53 6A 40 8D 85 44 FF FF FF 50 E8 BC FF FF FF 50 E8 8A FF FF FF 68 F8 00 00 00 8D 85 4C FE FF FF 50 E8 A5 FF FF FF 03 45 80 50 E8 70 FF FF FF E8 97 FF FF FF 03 85 CC FE FF FF 83 C0 34 89 45 FC E8 86 FF FF FF 03 85 CC FE FF FF 83 C0 38 89 45 8C 60 8B 45 FC 8B 00 89 45 F8 89 45 9C 8B 45 8C 8B 00 89 45 88 89 45 98 E8 0D 00 00 00 6B 65 72 6E 65 6C 33 }
	condition:
		$a0
}

rule pe123_44
{
	meta:
		author = "PEiD"
		description = "Pe123 2006.4.4"
		group = "444"
		function = "0"
	strings:
		$a0 = { 8B C0 EB 01 34 60 EB 01 2A 9C EB 02 EA C8 E8 0F 00 00 00 EB 03 3D 23 23 EB 01 4A EB 01 5B C3 8D 40 00 53 EB 01 6C EB 01 7E EB 01 8F E8 15 01 00 00 50 E8 67 04 00 00 EB 01 9A 8B D8 FF D3 5B C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 55 8B EC 60 8B 4D 10 8B 7D 0C 8B 75 08 F3 A4 61 5D C2 0C 00 E8 00 00 00 00 58 83 E8 05 C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 E8 00 00 00 00 58 C1 E8 0C C1 E0 0C 66 81 38 4D 5A 74 0C 2D 00 10 00 00 66 81 38 4D 5A 75 F4 C3 E8 00 00 00 00 58 83 E8 05 C3 8B C0 55 8B EC 81 C4 B8 FE FF FF 6A 40 8D 45 B0 50 E8 C0 FF FF FF 50 E8 8E FF FF FF 68 F8 00 00 00 8D 85 B8 FE FF FF 50 E8 A9 FF FF FF 03 45 EC 50 E8 74 FF FF FF E8 9B FF FF FF 03 85 38 FF FF FF 83 C0 34 89 45 FC E8 8A FF FF FF 03 85 38 FF FF FF 83 C0 38 89 45 F4 8B 45 FC }
	condition:
		$a0
}

rule pe123_44_412
{
	meta:
		author = "PEiD"
		description = "Pe123 2006.4.4-4.12"
		group = "444"
		function = "0"
	strings:
		$a0 = { 8B C0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? C0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF ?? ?? ?? 45 ?? 50 E8 ?? FF FF FF ?? ?? ?? FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 45 }
	condition:
		$a0
}

rule polycryptpe
{
	meta:
		author = "PEiD"
		description = "PolyCrypt PE 2005 -> JLab Software"
		group = "444"
		function = "20"
	strings:
		$a0 = { 60 E8 ED FF FF FF EB }
	condition:
		$a0
}

rule pbasic702
{
	meta:
		author = "PEiD"
		description = "PowerBasic 7.02"
		group = "117"
		function = "0"
	strings:
		$a0 = { 55 8B EC 53 56 57 BB ?? ?? ?? ?? 66 2E F7 ?? ?? ?? ?? 00 04 00 0F 85 }
	condition:
		$a0
}

rule pbasic800
{
	meta:
		author = "PEiD"
		description = "PowerBASIC/Win 8.00"
		group = "555"
		function = "0"
	strings:
		$a0 = { 55 8B EC 53 56 57 BB 00 ?? ?? 00 66 2E F7 05 ?? ?? 40 00 04 00 75 05 E9 14 04 00 00 E9 19 02 }
	condition:
		$a0
}

rule pbasiccc40
{
	meta:
		author = "PEiD"
		description = "PowerBASIC/CC 4.0"
		group = "555"
		function = "0"
	strings:
		$a0 = { 55 8B EC 53 56 57 BB 00 ?? 40 00 66 2E F7 05 ?? ?? 40 00 04 00 75 05 E9 68 05 00 00 E9 6E 03 }
	condition:
		$a0
}

rule wcrt
{
	meta:
		author = "PEiD"
		description = "WCRT Library (Visual C++) Method 1 -> Jibz"
		group = "17"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 EC 44 A1 ?? ?? ?? ?? 85 C0 74 ?? FF D0 85 C0 75 ?? 6A FE EB ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 }
	condition:
		$a0
}

rule wcrt_dll
{
	meta:
		author = "PEiD"
		description = "WCRT Library (Visual C++) DLL Method 1 -> Jibz"
		group = "17"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 7D 0C 01 75 ?? A1 ?? ?? ?? ?? 85 C0 74 ?? FF D0 85 C0 75 ?? 6A FE EB ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 }
	condition:
		$a0
}

rule wcrt1
{
	meta:
		author = "PEiD"
		description = "WCRT Library (Visual C++) Method 2 -> Jibz"
		group = "17"
		function = "0"
	strings:
		$a0 = { 55 8B EC 51 A1 ?? ?? ?? ?? 85 C0 74 ?? FF D0 85 C0 75 ?? 6A FE EB ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 }
	condition:
		$a0
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

rule ming_gcc2
{
	meta:
		author = "PEiD"
		description = "MingWin32 GCC 2.x"
		group = "21"
		function = "0"
	strings:
		$a0 = { 55 89 E5 E8 ?? ?? ?? ?? C9 C3 ?? ?? 45 58 45 }
	condition:
		$a0 at pe.entry_point
}

rule ming_gcc3
{
	meta:
		author = "PEiD"
		description = "MingWin32 GCC 3.x"
		group = "21"
		function = "0"
	strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? ?? ?? E8 68 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 }
	condition:
		$a0 at pe.entry_point
}

rule _32lite
{
	meta:
		author = "PEiD"
		description = "32Lite 0.03a -> Oleg Prokhorov"
		group = "101"
		function = "0"
	strings:
		$a0 = { 60 06 FC 1E 07 BE ?? ?? ?? ?? 6A 04 68 ?? 10 ?? ?? 68 }
	condition:
		$a0 at pe.entry_point
}

rule acidcrypt
{
	meta:
		author = "PEiD"
		description = "AcidCrypt -> AciDLeo"
		group = "102"
		function = "0"
	strings:
		$a0 = { BE ?? ?? ?? ?? 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0 CB }
	condition:
		$a0
}

rule acprotect_109g
{
	meta:
		author = "PEiD"
		description = "ACProtect 1.09g -> Risco software Inc."
		group = "444"
		function = "0"
	strings:
		$a0 = { 60 F9 50 E8 01 00 00 00 7C 58 58 49 50 E8 01 00 00 00 7E 58 58 79 04 66 B9 B8 72 E8 01 00 00 00 7A 83 C4 04 85 C8 EB 01 EB C1 F8 BE 72 03 73 01 74 0F 81 01 00 00 00 F9 EB 01 75 F9 E8 01 00 00 }
	condition:
		$a0
}

rule acprotect_190g
{
	meta:
		author = "PEiD"
		description = "ACProtect 1.90g -> Risco software Inc."
		group = "444"
		function = "0"
	strings:
		$a0 = { 60 0F 87 02 00 00 00 1B F8 E8 01 00 00 00 73 83 04 24 06 C3 }
	condition:
		$a0
}

rule ahpack
{
	meta:
		author = "PEiD"
		description = "AHpack 0.1 -> FEUERRADER"
		group = "444"
		function = "0"
	strings:
		$a0 = { 60 68 54 ?? ?? ?? B8 48 ?? ?? ?? FF 10 68 B3 ?? ?? ?? 50 B8 44 ?? ?? ?? FF 10 68 00 ?? ?? ?? 6A 40 FF D0 89 05 CA ?? ?? ?? 89 C7 BE 00 10 ?? ?? 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 89 E8 B3 01 56 89 FE 29 C6 F3 A4 5E EB 8E 00 D2 75 05 8A 16 46 10 D2 C3 }
	condition:
		$a0
}

rule alexp10b2
{
	meta:
		author = "PEiD"
		description = "Alex Protector 1.0 beta2"
		group = "444"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 10 40 ?? E8 24 00 00 00 EB 01 E9 8B 44 24 0C EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 83 80 B8 ?? ?? ?? 02 33 }
	condition:
		$a0
}

rule alloy
{
	meta:
		author = "PEiD"
		description = "Alloy 1.x.2000 -> Prakash Gautam"
		group = "302"
		function = "0"
	strings:
		$a0 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 ?? 87 DD 6A 04 68 ?? 10 ?? ?? 68 ?? 02 ?? ?? 6A ?? FF 95 46 23 40 ?? 0B }
	condition:
		$a0 at pe.entry_point
}

rule alloy_4x
{
	meta:
		author = "PEiD"
		description = "Alloy 4.x -> PGWare LLC"
		group = "444"
		function = "0"
	strings:
		$a0 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 6A 04 68 00 10 00 00 68 00 02 00 00 6A 00 FF 95 A8 33 40 00 0B C0 0F 84 F6 01 00 00 89 85 2E 33 40 00 83 BD E8 32 40 00 01 74 0D 83 BD E4 32 40 00 01 74 2A 8B F8 EB 3E 68 D8 01 00 00 50 FF 95 CC 33 40 00 50 8D 85 28 33 40 00 50 FF B5 2E 33 40 00 FF 95 D0 33 40 00 58 83 C0 05 EB 0C 68 D8 01 00 00 50 FF 95 C0 33 40 00 8B BD 2E 33 40 00 03 F8 C6 07 5C 47 8D B5 00 33 40 00 AC 0A C0 74 03 AA EB F8 83 BD DC 32 40 00 01 74 7A 6A }
	condition:
		$a0
}

rule antidote12demo
{
	meta:
		author = "PEiD"
		description = "AntiDote 1.2 Demo -> SIS-Team"
		group = "2006"
		function = "0"
	strings:
		$a0 = { E8 F7 FE FF FF 05 CB 22 00 00 FF E0 E8 EB FE FF FF 05 BB 19 00 00 FF E0 E8 BD 00 00 00 08 B2 62 00 01 52 17 0C 0F 2C 2B 20 7F 52 79 01 30 07 17 29 4F 01 3C 30 2B 5A 3D C7 26 11 26 06 59 0E 78 2E 10 14 0B 13 1A 1A 3F 64 1D 71 33 57 21 09 24 8B 1B 09 37 08 61 0F 1D 1D 2A 01 87 35 4C 07 39 0B }
	condition:
		$a0
}

rule ansfc
{
	meta:
		author = "PEiD"
		description = "Anslym FUD Crypter"
		group = "2006"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 B8 38 17 05 10 E8 5A 45 FB FF 33 C0 55 68 21 1C 05 10 64 FF 30 64 89 20 EB 08 FC FC FC FC FC FC 27 54 E8 85 4C FB FF 6A 00 E8 0E 47 FB FF 6A 0A E8 27 49 FB FF E8 EA 47 FB FF 6A 0A }
	condition:
		$a0
}

rule armprot01
{
	meta:
		author = "PEiD"
		description = "ARM Protector 0.1 -> SMoKE"
		group = "100"
		function = "0"
	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 5E 1F 40 00 EB 02 }
	condition:
		$a0 at pe.entry_point
}

rule aspack_100b
{
	meta:
		author = "PEiD"
		description = "ASPack 1.00b -> Alexey Solodovnikov"
		group = "100"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 92 1A 44 ?? B8 8C 1A 44 ?? 03 C5 2B 85 CD 1D 44 ?? 89 85 D9 1D 44 ?? 80 BD C4 1D 44 }
	condition:
		$a0 at pe.entry_point
}

rule aspack_101b
{
	meta:
		author = "PEiD"
		description = "ASPack 1.01b -> Alexey Solodovnikov"
		group = "100"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED D2 2A 44 ?? B8 CC 2A 44 ?? 03 C5 2B 85 A5 2E 44 ?? 89 85 B1 2E 44 ?? 80 BD 9C 2E 44 }
	condition:
		$a0 at pe.entry_point
}

rule aspack_102a
{
	meta:
		author = "PEiD"
		description = "ASPack 1.02a -> Alexey Solodovnikov"
		group = "100"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 3E D9 43 ?? B8 38 ?? ?? ?? 03 C5 2B 85 0B DE 43 ?? 89 85 17 DE 43 ?? 80 BD 01 DE 43 ?? ?? 75 15 FE 85 01 DE 43 ?? E8 1D ?? ?? ?? E8 79 02 ?? ?? E8 12 03 ?? ?? 8B 85 03 DE 43 ?? 03 85 17 DE 43 ?? 89 44 24 1C 61 FF }
	condition:
		$a0
}

rule aspack_102b
{
	meta:
		author = "PEiD"
		description = "ASPack 1.02b -> Alexey Solodovnikov"
		group = "100"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 96 78 43 ?? B8 90 78 43 ?? 03 C5 2B 85 7D 7C 43 ?? 89 85 89 7C 43 ?? 80 BD 74 7C 43 }
	condition:
		$a0 at pe.entry_point
}

rule aspack_103b
{
	meta:
		author = "PEiD"
		description = "ASPack 1.03b -> Alexey Solodovnikov"
		group = "100"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED CE 3A 44 ?? B8 C8 3A 44 ?? 03 C5 2B 85 B5 3E 44 ?? 89 85 C1 3E 44 ?? 80 BD AC 3E 44 }
	condition:
		$a0 at pe.entry_point
}

rule aspack_104b
{
	meta:
		author = "PEiD"
		description = "ASPack 1.04b -> Alexey Solodovnikov"
		group = "100"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85 12 9D ?? ?? 89 85 1E 9D ?? ?? 80 BD 08 9D }
	condition:
		$a0 at pe.entry_point
}

rule aspack_105b
{
	meta:
		author = "PEiD"
		description = "ASPack 1.05b -> Alexey Solodovnikov"
		group = "100"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED AE 98 43 ?? B8 A8 98 43 ?? 03 C5 2B 85 18 9D 43 ?? 89 85 24 9D 43 ?? 80 BD 0E 9D 43 }
	condition:
		$a0 at pe.entry_point
}

rule aspack_1061b
{
	meta:
		author = "PEiD"
		description = "ASPack 1.061b -> Alexey Solodovnikov"
		group = "100"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED EA A8 43 ?? B8 E4 A8 43 ?? 03 C5 2B 85 78 AD 43 ?? 89 85 84 AD 43 ?? 80 BD 6E AD 43 }
	condition:
		$a0 at pe.entry_point
}

rule aspack_107b
{
	meta:
		author = "PEiD"
		description = "ASPack 1.07b -> Alexey Solodovnikov"
		group = "100"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85 0B DE ?? ?? 89 85 17 DE ?? ?? 80 BD 01 DE }
	condition:
		$a0 at pe.entry_point
}

rule aspack_10800
{
	meta:
		author = "PEiD"
		description = "ASPack 1.08.00 -> Alexey Solodovnikov"
		group = "105"
		function = "0"
	strings:
		$a0 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ED 23 EA 44 ?? BB 10 EA 44 ?? 03 DD 2B 9D }
	condition:
		$a0 at pe.entry_point
}

rule aspack_10801
{
	meta:
		author = "PEiD"
		description = "ASPack 1.08.01 -> Alexey Solodovnikov"
		group = "105"
		function = "0"
	strings:
		$a0 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ED 23 6A 44 ?? BB 10 6A 44 ?? 03 DD 2B 9D 72 }
	condition:
		$a0 at pe.entry_point
}

rule aspack_10802
{
	meta:
		author = "PEiD"
		description = "ASPack 1.08.02 -> Alexey Solodovnikov"
		group = "105"
		function = "0"
	strings:
		$a0 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ED 23 6A 44 ?? BB 10 6A 44 ?? 03 DD 2B 9D 46 }
	condition:
		$a0 at pe.entry_point
}

rule aspack_10803
{
	meta:
		author = "PEiD"
		description = "ASPack 1.08.03 -> Alexey Solodovnikov"
		group = "105"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 0A 4A 44 ?? BB 04 4A 44 ?? 03 DD 2B 9D B1 50 44 ?? 83 BD AC 50 44 ?? ?? 89 9D BB 4E }
	condition:
		$a0 at pe.entry_point
}

rule aspack_10804
{
	meta:
		author = "PEiD"
		description = "ASPack 1.08.04 -> Alexey Solodovnikov"
		group = "105"
		function = "0"
	strings:
		$a0 = { 60 E8 41 06 ?? ?? EB 41 }
	condition:
		$a0
}

rule aspack_108x
{
	meta:
		author = "PEiD"
		description = "ASPack 1.08.x -> Alexey Solodovnikov"
		group = "105"
		function = "0"
	strings:
		$a0 = { 60 EB 03 5D FF E5 E8 F8 FF FF FF 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D }
	condition:
		$a0
}

rule aspack_10567
{
	meta:
		author = "PEiD"
		description = "ASPack 1.05b - 1.07b -> Alexey Solodovnikov"
		group = "105"
		function = "2"
	strings:
		$a0 = { 75 00 E9 }
	condition:
		$a0
}

rule aspack_10567a
{
	meta:
		author = "PEiD"
		description = "ASPack 1.05b - 1.07b -> Alexey Solodovnikov"
		group = "105"
		function = "2"
	strings:
		$a0 = { 90 75 00 E9 }
	condition:
		$a0
}

rule aspack_10567b
{
	meta:
		author = "PEiD"
		description = "ASPack 1.05b - 1.07b -> Alexey Solodovnikov"
		group = "105"
		function = "2"
	strings:
		$a0 = { ?? 90 75 00 E9 }
	condition:
		$a0
}

rule aspack_10567c
{
	meta:
		author = "PEiD"
		description = "ASPack 1.05b - 1.07b -> Alexey Solodovnikov"
		group = "105"
		function = "2"
	strings:
		$a0 = { ?? ?? 90 75 00 E9 }
	condition:
		$a0
}

rule aspack_108a
{
	meta:
		author = "PEiD"
		description = "ASPack 1.08.00 - 1.08.04 -> Alexey Solodovnikov"
		group = "105"
		function = "1"
	strings:
		$a0 = { 90 75 01 ?? E9 }
	condition:
		$a0
}

rule aspack_108b
{
	meta:
		author = "PEiD"
		description = "ASPack 1.08.00 - 1.08.04 -> Alexey Solodovnikov"
		group = "105"
		function = "1"
	strings:
		$a0 = { ?? 90 75 01 ?? E9 }
	condition:
		$a0
}

rule aspack_108c
{
	meta:
		author = "PEiD"
		description = "ASPack 1.08.00 - 1.08.04 -> Alexey Solodovnikov"
		group = "105"
		function = "1"
	strings:
		$a0 = { ?? ?? 90 75 01 ?? E9 }
	condition:
		$a0
}

rule aspack_2000
{
	meta:
		author = "PEiD"
		description = "ASPack 2.000 -> Alexey Solodovnikov"
		group = "105"
		function = "0"
	strings:
		$a0 = { 60 E8 70 05 ?? ?? EB 4C ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 87 DB 90 }
	condition:
		$a0
}

rule aspack_20011
{
	meta:
		author = "PEiD"
		description = "ASPack 2.001 -> Alexey Solodovnikov"
		group = "105"
		function = "0"
	strings:
		$a0 = { 60 E8 72 05 ?? ?? EB 4C ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 87 DB 90 }
	condition:
		$a0
}

rule aspack_2001
{
	meta:
		author = "PEiD"
		description = "ASPack 2.00.1 -> Alexey Solodovnikov"
		group = "105"
		function = "0"
	strings:
		$a0 = { 60 E8 3B 05 ?? ?? EB 48 ?? ?? ?? ?? ?? ?? ?? ?? 87 DB 90 }
	condition:
		$a0
}

rule aspack_21
{
	meta:
		author = "PEiD"
		description = "ASPack 2.1 -> Alexey Solodovnikov"
		group = "105"
		function = "0"
	strings:
		$a0 = { 60 E8 72 05 ?? ?? EB 33 87 DB 90 }
	condition:
		$a0
}

rule aspack_21h
{
	meta:
		author = "PEiD"
		description = "ASPack 2.1 Modified -> Alexey Solodovnikov"
		group = "105"
		function = "0"
	strings:
		$a0 = { BB ?? ?? ?? ?? 03 DD 2B 9D ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8B F8 8D 9D ?? ?? ?? ?? 53 50 FF 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 53 57 FF 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? FF E0 }
	condition:
		$a0 at pe.entry_point
}

rule aspack_211
{
	meta:
		author = "PEiD"
		description = "ASPack 2.11 -> Alexey Solodovnikov"
		group = "100"
		function = "0"
	strings:
		$a0 = { 60 E9 3D 04 }
	condition:
		$a0
}

rule aspack_211b
{
	meta:
		author = "PEiD"
		description = "ASPack 2.11b -> Alexey Solodovnikov"
		group = "100"
		function = "0"
	strings:
		$a0 = { 60 E8 02 ?? ?? ?? EB 09 5D 55 81 ED 39 39 44 ?? C3 E9 3D 04 }
	condition:
		$a0 at pe.entry_point
}

rule aspack_211c
{
	meta:
		author = "PEiD"
		description = "ASPack 2.11c -> Alexey Solodovnikov"
		group = "100"
		function = "0"
	strings:
		$a0 = { 60 E8 02 ?? ?? ?? EB 09 5D 55 81 ED 39 39 44 ?? C3 E9 59 04 }
	condition:
		$a0 at pe.entry_point
}

rule aspack_211d
{
	meta:
		author = "PEiD"
		description = "ASPack 2.11d -> Alexey Solodovnikov"
		group = "100"
		function = "0"
	strings:
		$a0 = { 60 E8 02 ?? ?? ?? EB 09 5D 55 }
	condition:
		$a0
}

rule asprotect_ske_211_dll
{
	meta:
		author = "PEiD"
		description = "ASProtect SKE 2.1x (DLL) -> Alexey Solodovnikov"
		group = "444"
		function = "0"
	strings:
		$a0 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ?? 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 B8 F8 C0 A5 23 50 50 03 45 4E 5B 85 C0 74 1C EB 01 E8 81 FB F8 C0 A5 23 74 35 33 D2 56 6A 00 56 FF 75 4E FF D0 5E 83 FE 00 75 24 33 D2 8B 45 41 85 C0 74 07 52 52 FF 75 35 FF D0 8B 45 35 85 C0 74 0D 68 00 80 00 00 6A 00 FF 75 35 FF 55 3D 5B 0B DB 61 75 06 6A 01 58 C2 0C 00 33 C0 F7 D8 1B C0 40 C2 0C 00 }
	condition:
		$a0
}

rule aspack_212
{
	meta:
		author = "PEiD"
		description = "ASPack 2.12 -> Alexey Solodovnikov"
		group = "100"
		function = "6"
	strings:
		$a0 = { 60 E8 03 ?? ?? ?? E9 EB 04 5D 45 55 C3 E8 01 ?? ?? ?? EB 5D BB ED FF FF FF 03 DD 81 EB }
	condition:
		$a0
}

rule aspack_212b
{
	meta:
		author = "PEiD"
		description = "ASPack 2.12b -> Alexey Solodovnikov"
		group = "100"
		function = "6"
	strings:
		$a0 = { 90 60 E8 03 ?? ?? ?? E9 EB 04 5D 45 55 C3 E8 01 ?? ?? ?? EB 5D BB EC FF FF FF 03 DD 81 EB }
	condition:
		$a0
}

rule aspack_2x
{
	meta:
		author = "PEiD"
		description = "ASPack 2.xx Heuristic Mode -> Alexey Solodovnikov"
		group = "105"
		function = "0"
	strings:
		$a0 = { A8 03 ?? ?? 61 75 08 B8 01 ?? ?? ?? C2 0C ?? 68 ?? ?? ?? ?? C3 8B 85 26 04 ?? ?? 8D 8D 3B 04 ?? ?? 51 50 FF 95 }
	condition:
		$a0 at pe.entry_point
}

rule sircam
{
	meta:
		author = "PEiD"
		description = "WARNING -> VIRUS -> W32@Sircam_mm"
		group = "800"
		function = "0"
	strings:
		$a0 = { 55 8B EC B9 41 ?? ?? ?? 6A ?? 6A ?? 49 75 F9 51 53 56 57 B8 D4 A8 41 ?? E8 BF B0 FE FF BE }
	condition:
		$a0
}

rule aspr1
{
	meta:
		author = "PEiD"
		description = "ASProtect 1.0 -> Alexey Solodovnikov"
		group = "106"
		function = "0"
	strings:
		$a0 = { 60 E8 01 ?? ?? ?? 90 5D 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D }
	condition:
		$a0
}

rule aspr11
{
	meta:
		author = "PEiD"
		description = "ASProtect 1.1 -> Alexey Solodovnikov"
		group = "106"
		function = "0"
	strings:
		$a0 = { 60 E9 ?? 04 ?? ?? E9 ?? ?? ?? ?? ?? ?? ?? EE }
	condition:
		$a0
}

rule aspr11_mte
{
	meta:
		author = "PEiD"
		description = "ASProtect 1.1 MTE -> Alexey Solodovnikov"
		group = "106"
		function = "3"
	strings:
		$a0 = { 60 E9 ?? ?? ?? ?? 91 78 79 79 79 E9 }
	condition:
		$a0
}

rule aspr11b
{
	meta:
		author = "PEiD"
		description = "ASProtect 1.1b MTE -> Alexey Solodovnikov"
		group = "106"
		function = "3"
	strings:
		$a0 = { 60 E9 ?? 04 }
	condition:
		$a0
}

rule aspr11c
{
	meta:
		author = "PEiD"
		description = "ASProtect 1.1c MTE -> Alexey Solodovnikov"
		group = "106"
		function = "3"
	strings:
		$a0 = { 60 E8 1B ?? ?? ?? E9 FC }
	condition:
		$a0
}

rule aspr11_brs
{
	meta:
		author = "PEiD"
		description = "ASProtect 1.1 brs -> Alexey Solodovnikov"
		group = "106"
		function = "3"
	strings:
		$a0 = { 60 E9 ?? 05 }
	condition:
		$a0
}

rule aspr12
{
	meta:
		author = "PEiD"
		description = "ASProtect 1.2 -> Alexey Solodovnikov"
		group = "106"
		function = "3"
	strings:
		$a0 = { 68 01 ?? ?? ?? C3 }
	condition:
		$a0
}

rule aspr12x
{
	meta:
		author = "PEiD"
		description = "ASProtect 1.2x -> Alexey Solodovnikov"
		group = "106"
		function = "3"
	strings:
		$a0 = { ?? ?? 68 01 ?? ?? ?? C3 AA }
	condition:
		$a0
}

rule aspr12_h
{
	meta:
		author = "PEiD"
		description = "ASProtect 1.2x [New Strain] -> Alexey Solodovnikov"
		group = "106"
		function = "3"
	strings:
		$a0 = { 68 01 ?? ?? ?? E8 01 ?? ?? ?? C3 C3 }
	condition:
		$a0
}

rule asprstrip
{
	meta:
		author = "PEiD"
		description = "ASPR Stripper 2.xx unpacked -> syd"
		group = "106"
		function = "0"
	strings:
		$a0 = { BB ?? ?? ?? ?? E9 ?? ?? ?? ?? 60 9C FC BF ?? ?? ?? ?? B9 ?? ?? ?? ?? F3 AA 9D 61 C3 55 8B EC }
	condition:
		$a0
}

rule bambam001
{
	meta:
		author = "PEiD"
		description = "bambam 0.01 -> bedrock"
		group = "444"
		function = "0"
	strings:
		$a0 = { 6A 14 E8 9A 05 00 00 8B D8 53 68 FB ?? ?? 00 E8 6C FD FF FF B9 05 00 00 00 8B F3 BF FB ?? ?? 00 53 F3 A5 E8 8D 05 00 00 8B 3D 03 ?? ?? 00 A1 2B ?? ?? 00 66 8B 15 2F ?? ?? 00 B9 80 ?? ?? 00 2B }
	condition:
		$a0
}

rule bambam004
{
	meta:
		author = "PEiD"
		description = "bambam 0.04 -> bedrock"
		group = "2006"
		function = "0"
	strings:
		$a0 = { BF ?? ?? ?? ?? 83 C9 FF 33 C0 68 ?? ?? ?? ?? F2 AE F7 D1 49 51 68 ?? ?? ?? ?? E8 11 0A 00 00 83 C4 0C 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B F0 BF ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 49 BF ?? ?? ?? ?? 8B D1 68 ?? ?? ?? ?? C1 E9 02 F3 AB 8B CA 83 E1 03 F3 AA BF ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 49 51 68 ?? ?? ?? ?? E8 C0 09 00 00 }
	condition:
		$a0
}

rule beria007
{
	meta:
		author = "PEiD"
		description = "beria 0.07 public WIP -> symbiont"
		group = "999"
		function = "0"
	strings:
		$a0 = { 83 EC 18 53 8B 1D 00 30 ?? ?? 55 56 57 68 30 07 00 00 33 ED 55 FF D3 8B F0 3B F5 74 0D 89 AE 20 07 00 00 E8 88 0F 00 00 EB 02 33 F6 6A 10 55 89 35 30 40 ?? ?? FF D3 8B F0 3B F5 74 09 89 2E E8 3C FE FF FF EB 02 33 F6 6A 18 55 89 35 D8 43 ?? ?? FF D3 8B F0 3B F5 74 37 8B 46 0C 3B C5 8B 3D 04 30 ?? ?? 89 2E 89 6E 04 89 6E 08 74 06 50 FF D7 89 6E 0C 8B 46 10 3B C5 74 06 50 FF D7 89 6E 10 8B 46 14 3B C5 74 0A 50 FF D7 89 6E 14 EB 02 33 F6 6A 10 55 89 35 A4 40 ?? ?? FF D3 8B F0 3B F5 74 09 E8 08 12 00 00 8B C6 EB 02 33 C0 8B 48 08 8B 51 04 8B 09 8B 35 30 30 ?? ?? A3 D4 43 ?? ?? 8B 00 03 D0 52 03 C8 51 FF D6 8B 3D 24 30 ?? ?? 50 FF D7 }
	condition:
		$a0
}

rule bjfnt11b
{
	meta:
		author = "PEiD"
		description = ".BJFNT 1.1b -> :MARQUiS:"
		group = "107"
		function = "0"
	strings:
		$a0 = { EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 }
	condition:
		$a0
}

rule bjfnt12rc
{
	meta:
		author = "PEiD"
		description = ".BJFNT 1.2rc -> :MARQUiS:"
		group = "107"
		function = "0"
	strings:
		$a0 = { EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB }
	condition:
		$a0 at pe.entry_point
}

rule bjfnt13
{
	meta:
		author = "PEiD"
		description = ".BJFNT 1.3 -> :MARQUiS:"
		group = "107"
		function = "0"
	strings:
		$a0 = { EB 03 3A 4D 3A 1E EB 02 CD 20 9C EB 02 CD 20 EB 02 CD 20 60 }
	condition:
		$a0 at pe.entry_point
}

rule bldjnr15
{
	meta:
		author = "PEiD"
		description = "Blade Joiner 1.5"
		group = "303"
		function = "0"
	strings:
		$a0 = { 55 8B EC 81 C4 E4 FE FF FF 53 56 57 33 C0 89 45 F0 89 85 }
	condition:
		$a0 at pe.entry_point
}

rule cavisobj
{
	meta:
		author = "PEiD"
		description = "CA Visual Objects 2.0 - 2.5"
		group = "555"
		function = "0"
	strings:
		$a0 = { 89 25 ?? ?? ?? ?? 33 ED 55 8B EC E8 ?? ?? ?? ?? 8B D0 81 E2 FF 00 00 00 89 15 ?? ?? ?? ?? 8B D0 C1 EA 08 81 E2 FF 00 00 00 A3 ?? ?? ?? ?? D1 E0 0F 93 C3 33 C0 8A C3 A3 ?? ?? ?? ?? 68 FF 00 00 00 E8 ?? ?? ?? ?? 6A 00 E8 }
	condition:
		$a0
}

rule cdcops
{
	meta:
		author = "PEiD"
		description = "CD-Cops II -> Link Data Security"
		group = "108"
		function = "0"
	strings:
		$a0 = { 53 60 BD ?? ?? ?? ?? 8D 45 ?? 8D 5D ?? E8 ?? ?? ?? ?? 8D }
	condition:
		$a0
}

rule cexe10a
{
	meta:
		author = "PEiD"
		description = "CExe 1.0a - 1.0b -> Tinyware Inc."
		group = "109"
		function = "0"
	strings:
		$a0 = { 55 8B EC 81 EC 0C 02 ?? ?? 56 BE 04 01 ?? ?? 8D 85 F8 FE FF FF 56 50 6A ?? FF 15 54 10 40 ?? 8A 8D F8 FE FF FF 33 D2 84 C9 8D 85 F8 FE FF FF 74 16 }
	condition:
		$a0
}

rule codecr014b
{
	meta:
		author = "PEiD"
		description = "CodeCrypt 0.14B -> defiler"
		group = "110"
		function = "0"
	strings:
		$a0 = { E9 C5 02 ?? ?? EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F }
	condition:
		$a0 at pe.entry_point
}

rule codecr015b
{
	meta:
		author = "PEiD"
		description = "CodeCrypt 0.15B -> defiler"
		group = "110"
		function = "0"
	strings:
		$a0 = { E9 31 03 ?? ?? EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F }
	condition:
		$a0 at pe.entry_point
}

rule codecr0164
{
	meta:
		author = "PEiD"
		description = "CodeCrypt 0.164 -> defiler"
		group = "110"
		function = "0"
	strings:
		$a0 = { E9 2E 03 ?? ?? EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F EB 03 FF 1D 34 }
	condition:
		$a0 at pe.entry_point
}

rule copyminder
{
	meta:
		author = "PEiD"
		description = "CopyMinder -> Microcosm.Ltd"
		group = "2006"
		function = "0"
	strings:
		$a0 = { 83 25 ?? ?? ?? ?? EF 6A 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? CC FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 }
	condition:
		$a0
}

rule crypteur1
{
	meta:
		author = "PEiD"
		description = "Crypteur 1.00 -> Morgatte"
		group = "110"
		function = "0"
	strings:
		$a0 = { 68 ?? ?? ?? ?? 5F 68 ?? ?? ?? ?? 58 33 DB EB 0D 8A 14 03 80 EA 07 80 F2 04 88 14 03 43 81 FB ?? ?? ?? ?? 72 EB 68 ?? ?? ?? ?? 5E FF E6 }
	condition:
		$a0 at pe.entry_point
}

rule crunch1_pe
{
	meta:
		author = "PEiD"
		description = "Crunch/PE 1.0.0.x -> Bit-Arts"
		group = "111"
		function = "0"
	strings:
		$a0 = { 55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 80 BD ?? ?? ?? ?? ?? 75 09 C6 85 }
	condition:
		$a0 at pe.entry_point
}

rule crunch2_pe
{
	meta:
		author = "PEiD"
		description = "Crunch/PE 2.0.0.x -> Bit-Arts"
		group = "111"
		function = "0"
	strings:
		$a0 = { 55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 55 BB ?? ?? ?? ?? 03 DD 53 64 67 FF 36 ?? ?? 64 67 89 26 }
	condition:
		$a0 at pe.entry_point
}

rule crunch5
{
	meta:
		author = "PEiD"
		description = "Crunch 5.0.0 -> Bit-Arts"
		group = "111"
		function = "0"
	strings:
		$a0 = { EB 15 03 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 68 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 1D 00 00 00 8B C5 55 60 9C 2B 85 FC 07 00 00 89 85 E8 07 00 00 FF 74 24 2C E8 20 02 00 00 0F 82 94 06 00 00 E8 F3 04 00 00 49 0F 88 88 06 00 00 8B B5 E8 07 00 00 8B 56 3C 8D 8C 32 C8 00 00 00 83 39 00 74 50 8B D9 53 68 BB D4 C3 79 33 C0 50 E8 0E 04 00 00 50 8D 95 EC 07 00 00 52 6A 04 68 00 10 00 00 FF B5 E8 07 00 00 FF D0 58 5B C7 03 00 00 00 00 C7 43 04 00 00 00 00 8D 95 F0 07 00 00 52 FF B5 EC 07 00 00 68 00 10 00 00 FF B5 E8 07 00 00 FF D0 68 6C D9 B2 96 33 C0 50 E8 C1 03 00 00 89 85 A2 46 00 00 68 EC 49 7B 79 33 C0 50 E8 AE 03 00 00 89 85 9A 46 00 00 E8 04 06 00 00 E9 F3 05 00 00 51 52 53 33 C9 49 8B D1 33 C0 33 DB AC 32 C1 8A CD 8A EA 8A D6 B6 08 66 D1 EB 66 D1 D8 73 09 66 35 20 83 66 81 F3 B8 ED FE CE 75 EB 33 C8 33 D3 4F 75 D5 F7 D2 F7 D1 5B 8B C2 C1 C0 10 66 8B C1 5A 59 C3 68 03 02 00 00 E8 1D 05 00 00 0F 82 C6 02 00 00 96 8B 44 24 04 0F C8 8B D0 25 0F 0F 0F 0F 33 D0 C1 C0 08 0B C2 8B D0 25 33 }
	condition:
		$a0
}

rule crypkey
{
	meta:
		author = "PEiD"
		description = "CrypKey 5.x - 6.x -> CrypKey Inc."
		group = "111"
		function = "0"
	strings:
		$a0 = { E8 ?? ?? ?? ?? 58 83 E8 05 50 5F 57 8B F7 81 EF ?? ?? ?? ?? 83 C6 39 BA ?? ?? ?? ?? 8B DF B9 0B ?? ?? ?? 8B 06 }
	condition:
		$a0
}

rule crypwrap
{
	meta:
		author = "PEiD"
		description = "CrypWrap -> CrypKey Inc."
		group = "112"
		function = "0"
	strings:
		$a0 = { E8 B8 ?? ?? ?? E8 90 02 ?? ?? 83 F8 ?? 75 07 6A ?? E8 ?? ?? ?? ?? FF 15 49 8F 40 ?? A9 ?? ?? ?? 80 74 0E }
	condition:
		$a0
}

rule cki
{
	meta:
		author = "PEiD"
		description = "Crypkey Instant 6.x -> CrypKey Inc."
		group = "112"
		function = "0"
	strings:
		$a0 = { 8B 1D ?? ?? ?? ?? 83 FB ?? 75 1C C7 05 ?? ?? ?? ?? 01 ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 E8 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? C3 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0B C0 }
	condition:
		$a0 at pe.entry_point
}

rule ckstealth
{
	meta:
		author = "PEiD"
		description = "CrypKey Stealth -> CrypKey Inc."
		group = "112"
		function = "0"
	strings:
		$a0 = { 83 3D ?? ?? ?? ?? ?? 75 34 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 8B 44 24 04 A3 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 F8 ?? 75 18 B8 ?? ?? ?? ?? C2 0C ?? A1 ?? ?? ?? ?? 83 F8 02 75 06 FF 25 ?? ?? ?? ?? B8 01 ?? ?? ?? C2 0C }
	condition:
		$a0 at pe.entry_point
}

rule cicompress
{
	meta:
		author = "PEiD"
		description = "CICompress 1.0"
		group = "444"
		function = "0"
	strings:
		$a0 = { 6A 04 68 00 10 00 00 FF 35 9C 14 40 00 6A 00 FF 15 38 10 40 00 A3 FC 10 40 00 97 BE 00 20 40 00 E8 71 00 00 00 3B 05 9C 14 40 00 75 61 6A 00 6A 20 6A 02 6A 00 6A 03 68 00 00 00 C0 68 94 10 40 00 FF 15 2C 10 40 00 A3 F8 10 40 00 6A 00 68 F4 10 40 00 FF 35 9C 14 40 00 FF 35 FC 10 40 00 FF 35 F8 10 40 00 FF 15 34 10 40 00 FF 35 F8 10 40 00 FF 15 30 10 40 00 68 00 40 00 00 FF 35 9C 14 40 00 FF 35 FC 10 40 00 FF 15 3C 10 40 00 6A 00 FF 15 28 10 40 00 60 33 DB 33 C9 E8 7F 00 00 00 73 0A B1 08 E8 82 00 00 00 AA EB EF E8 6E 00 00 00 73 14 B1 04 E8 71 00 00 00 3C 00 74 EB 56 8B F7 2B F0 A4 5E EB D4 33 ED E8 51 00 00 00 72 10 B1 02 E8 54 00 00 00 3C 00 74 3B 8B E8 C1 C5 08 B1 08 E8 44 00 00 00 0B C5 50 33 ED E8 2E 00 00 00 72 0C B1 02 E8 31 00 00 00 8B E8 C1 C5 08 }
	condition:
		$a0
}

rule cipherwall_con_15
{
	meta:
		author = "PEiD"
		description = "CipherWall Self-Extrator/Decryptor (Console) 1.5"
		group = "444"
		function = "0"
	strings:
		$a0 = { 90 61 BE 00 10 42 00 8D BE 00 00 FE FF C7 87 C0 20 02 00 0B 6E 5B 9B 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 75 20 41 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 83 C1 02 81 FD 00 F3 FF FF 83 D1 01 8D 14 2F 83 FD FC 76 0F 8A 02 42 88 07 47 49 75 F7 E9 63 FF FF FF 90 8B 02 83 C2 04 89 07 83 C7 04 83 E9 04 77 F1 01 CF E9 4C FF FF FF 5E 89 F7 B9 12 10 00 00 8A 07 47 2C E8 3C 01 77 F7 80 3F 06 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 }
	condition:
		$a0
}

rule cipherwall_gui_15
{
	meta:
		author = "PEiD"
		description = "CipherWall Self-Extrator/Decryptor (GUI) 1.5"
		group = "444"
		function = "0"
	strings:
		$a0 = { 90 61 BE 00 10 42 00 8D BE 00 00 FE FF C7 87 C0 20 02 00 F9 89 C7 6A 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 75 20 41 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 83 C1 02 81 FD 00 F3 FF FF 83 D1 01 8D 14 2F 83 FD FC 76 0F 8A 02 42 88 07 47 49 75 F7 E9 63 FF FF FF 90 8B 02 83 C2 04 89 07 83 C7 04 83 E9 04 77 F1 01 CF E9 4C FF FF FF 5E 89 F7 B9 52 10 00 00 8A 07 47 2C E8 3C 01 77 F7 80 3F 0E 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 }
	condition:
		$a0
}

rule createinstall_stub
{
	meta:
		author = "PEiD"
		description = "CreateInstall Stub x.x"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 8B EC 81 EC 20 02 00 00 53 56 57 6A 00 FF 15 18 61 40 00 68 00 70 40 00 89 45 08 FF 15 14 61 40 00 85 C0 74 27 6A 00 A1 00 20 40 00 50 FF 15 3C 61 40 00 8B F0 6A 06 56 FF 15 38 61 40 00 6A 03 56 FF 15 38 61 40 00 E9 36 03 00 00 68 02 7F 00 00 33 F6 56 BF 00 30 00 00 FF 15 20 61 40 00 50 FF 15 2C 61 40 00 6A 04 57 68 00 FF 01 00 56 FF 15 CC 60 40 00 6A 04 A3 CC 35 40 00 57 68 00 0F 01 00 56 FF 15 CC 60 40 00 68 00 01 00 00 BE B0 3F 40 00 56 A3 C4 30 40 00 FF 75 08 FF 15 10 61 40 00 }
	condition:
		$a0
}

rule dbpe153
{
	meta:
		author = "PEiD"
		description = "DBPE 1.53 -> Ding Boy"
		group = "113"
		function = "0"
	strings:
		$a0 = { 9C 55 57 56 52 51 53 9C FA E8 ?? ?? ?? ?? 5D 81 ED 5B 53 40 ?? B0 ?? E8 ?? ?? ?? ?? 5E 83 C6 11 B9 27 ?? ?? ?? 30 06 46 49 75 FA }
	condition:
		$a0
}

rule dbpe210time
{
	meta:
		author = "PEiD"
		description = "DBPE 2.10 (Time) -> Ding Boy"
		group = "113"
		function = "0"
	strings:
		$a0 = { 9C 6A 10 73 0B EB 02 C1 51 E8 06 ?? ?? ?? C4 11 73 F7 5B CD 83 C4 04 EB 02 99 EB FF 0C 24 71 01 E8 79 E0 7A 01 75 83 C4 04 9D EB 01 75 68 5F 20 40 ?? E8 B0 EF FF FF 72 03 73 01 75 BE }
	condition:
		$a0
}

rule dbpe210
{
	meta:
		author = "PEiD"
		description = "DBPE 2.10 -> Ding Boy"
		group = "113"
		function = "0"
	strings:
		$a0 = { EB 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9C 55 57 56 52 51 53 9C E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? EB 58 75 73 65 72 33 32 2E 64 6C 6C ?? 4D 65 73 73 61 67 65 42 6F 78 41 ?? 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C ?? 53 6C 65 65 70 ?? 47 65 74 54 69 63 6B 43 6F 75 6E 74 }
	condition:
		$a0
}

rule dbpe233
{
	meta:
		author = "PEiD"
		description = "DBPE 2.33 -> Ding Boy"
		group = "113"
		function = "0"
	strings:
		$a0 = { EB 20 ?? ?? 40 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9C 55 57 56 52 51 53 9C E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 9C 6A 10 73 0B EB 02 C1 51 E8 06 ?? ?? ?? C4 11 73 F7 5B CD 83 C4 04 EB 02 99 EB FF 0C 24 71 01 E8 79 E0 7A 01 75 83 }
	condition:
		$a0
}

rule dbpe2x
{
	meta:
		author = "PEiD"
		description = "DBPE 2.x -> Ding Boy"
		group = "113"
		function = "0"
	strings:
		$a0 = { EB 20 ?? ?? 40 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9C 55 57 56 52 51 53 9C E8 ?? ?? ?? ?? 5D 81 ED }
	condition:
		$a0
}

rule crunch4_pe
{
	meta:
		author = "PEiD"
		description = "Crunch/PE 3.0.0.x - 4.0.0.x -> Bit-Arts"
		group = "111"
		function = "0"
	strings:
		$a0 = { EB 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 5D 81 ED 18 ?? ?? ?? 8B C5 55 60 9C 2B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? FF 74 }
	condition:
		$a0 at pe.entry_point
}

rule dp067
{
	meta:
		author = "PEiD"
		description = "DAEMON Protect 0.6.7 -> DAEMON/UG"
		group = "114"
		function = "0"
	strings:
		$a0 = { 60 60 9C 8C C9 32 C9 E3 0C 52 0F 01 4C 24 FE 5A 83 C2 0C 8B 1A 9D 61 }
	condition:
		$a0 at pe.entry_point
}

rule def100eng
{
	meta:
		author = "PEiD"
		description = "DEF 1.00 (Eng) -> bart/xt"
		group = "114"
		function = "0"
	strings:
		$a0 = { BE ?? 01 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 ?? ?? 40 00 C3 }
	condition:
		$a0
}

rule dxpack
{
	meta:
		author = "PEiD"
		description = "DxPack 1.0x"
		group = "115"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 8B FD 81 ED ?? ?? ?? ?? 2B B9 ?? ?? ?? ?? 81 EF ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 0F 84 }
	condition:
		$a0 at pe.entry_point
}

rule dual_10
{
	meta:
		author = "PEiD"
		description = "Dual's eXe 1.0"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 8B EC 81 EC 00 05 00 00 E8 00 00 00 00 5D 81 ED 0E 00 00 00 8D 85 08 03 00 00 89 28 33 FF 8D 85 7D 02 00 00 8D 8D 08 03 00 00 2B C8 8B 9D 58 03 00 00 E8 1C 02 00 00 8D 9D 61 02 00 00 8D B5 7C 02 00 00 46 80 3E 00 74 24 56 FF 95 0A 04 00 00 46 80 3E 00 75 FA 46 80 3E 00 74 E7 50 56 50 FF 95 0E 04 00 00 89 03 58 83 C3 04 EB E3 8D 85 24 03 00 00 50 68 1F 00 02 00 6A 00 8D 85 48 03 00 00 50 68 01 00 00 80 FF 95 69 02 00 00 83 BD 24 03 00 00 00 0F 84 8B 00 00 00 C7 85 28 03 00 00 04 00 00 00 8D 85 28 03 00 00 50 8D 85 20 03 00 00 50 8D 85 6C 03 00 00 50 6A 00 8D 85 62 03 00 00 50 FF B5 24 03 00 00 FF 95 71 02 00 00 83 BD 20 03 00 00 01 7E 02 EB 20 6A 40 8D 85 73 03 00 00 50 8D 85 82 03 00 00 50 6A 00 FF 95 61 02 00 00 6A 00 FF 95 65 02 00 00 FF 8D 20 03 00 00 FF }
	condition:
		$a0
}

rule enigma_112
{
	meta:
		author = "PEiD"
		description = "ENIGMA Protector 1.12-> Sukhov Vladimir"
		group = "444"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 C5 FA 81 ED ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 EB 02 FF 35 60 E8 24 00 00 00 00 00 FF EB 02 CD 20 8B 44 24 0C 83 80 B8 00 00 00 03 31 C0 C3 83 C0 08 EB 02 FF 15 89 C4 61 EB 2E EA EB 2B 83 04 24 03 EB 01 00 31 C0 EB 01 85 64 FF 30 EB }
	condition:
		$a0
}

rule exeguarder
{
	meta:
		author = "PEiD"
		description = "Exe Guarder 1.8 -> Exeicon.com"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 C4 D0 53 56 57 8D 75 FC 8B 44 24 30 25 00 00 FF FF 81 38 4D 5A 90 00 74 07 2D 00 10 00 00 EB F1 89 45 FC E8 C8 FF FF FF 2D B2 04 00 00 89 45 F4 8B 06 8B 40 3C 03 06 8B 40 78 03 06 8B C8 8B 51 20 03 16 8B 59 24 03 1E 89 5D F0 8B 59 1C 03 1E 89 5D EC 8B 41 18 8B C8 49 85 C9 72 5A 41 33 C0 8B D8 C1 E3 02 03 DA 8B 3B 03 3E 81 3F 47 65 74 50 75 40 8B DF 83 C3 04 81 3B 72 6F 63 41 75 33 8B DF 83 C3 08 81 3B 64 64 72 65 75 26 83 C7 0C 66 81 3F 73 73 75 1C 8B D0 03 D2 03 55 F0 0F B7 12 C1 E2 02 03 55 EC 8B 12 03 16 8B 4D F4 89 51 08 EB 04 40 49 75 A9 8B 5D F4 8D 83 A1 00 00 00 50 8B 06 50 FF 53 08 89 43 0C 8D 83 AE 00 00 00 50 8B 06 50 FF 53 08 89 43 10 8D 83 BA 00 00 00 50 8B 06 50 FF 53 08 89 43 14 8D 83 C6 00 00 00 50 8B 06 50 FF 53 08 89 43 18 8D 83 D7 00 00 00 50 8B 06 50 FF 53 08 89 43 1C 8D 83 E0 00 00 00 50 8B 06 50 FF 53 08 }
	condition:
		$a0
}

rule embedpe13
{
	meta:
		author = "PEiD"
		description = "EmbedPE 1.13 -> cyclotron"
		group = "444"
		function = "0"
	strings:
		$a0 = { 83 EC 50 60 68 5D B9 52 5A E8 2F 99 00 00 DC 99 F3 57 05 68 B8 5E 2D C6 DA FD 48 63 05 3C 71 B8 5E 97 7C 36 7E 32 7C 08 4F 06 51 64 10 A3 F1 4E CF 25 CB 80 D2 99 54 46 ED E1 D3 46 86 2D 10 68 93 83 5C 46 4D 43 9B 8C D6 7C BB 99 69 97 71 2A 2F A3 38 6B 33 A3 F5 0B 85 97 7C BA 1D 96 DD 07 F8 FD D2 3A 98 83 CC 46 99 9D DF 6F 89 92 54 46 9F 94 43 CC 41 43 9B 8C 61 B9 D8 6F 96 3B D1 07 32 24 DD 07 05 8E CB 6F A1 07 5C 62 20 E0 DB BA 9D 83 54 46 E6 83 51 7A 2B 94 54 64 8A 83 05 68 D7 5E 2D C6 B7 57 00 B3 E8 3C 71 B8 3C 97 7C 36 19 32 7C 08 2A 06 51 64 73 A3 F1 4E 92 25 CB 80 8D 99 54 46 B0 E1 D3 46 A5 2D 10 68 B6 83 91 46 F2 DF 64 FD D1 BC CA AA 70 E2 AB 39 AE 3B 5A 6F 9B 15 BD 25 98 25 30 4C AD 7D 55 07 A8 A3 AC 0A C1 BD 54 72 BC 83 54 82 A3 97 B1 1A B3 83 54 46 83 }
	condition:
		$a0
}

rule exelocker
{
	meta:
		author = "PEiD"
		description = "Exe Locker 1.0 -> IonIce"
		group = "555"
		function = "0"
	strings:
		$a0 = { E8 00 00 00 00 60 8B 6C 24 20 81 ED 05 00 00 00 3E 8F 85 6C 00 00 00 3E 8F 85 68 00 00 00 3E 8F 85 64 00 00 00 3E 8F 85 60 00 00 00 3E 8F 85 5C 00 00 00 3E 8F 85 58 00 00 00 3E 8F 85 54 00 00 }
	condition:
		$a0
}

rule exeshield02b
{
	meta:
		author = "PEiD"
		description = "EXE Shield 0.2b -> SMoKE"
		group = "116"
		function = "0"
	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D 81 ED 90 19 40 00 EB 01 00 8D B5 1A 1A 40 00 BA 1E 0A 00 00 EB 01 00 8D 8D 38 24 40 00 8B 09 E8 14 00 00 00 83 EB 01 }
	condition:
		$a0 at pe.entry_point
}

rule exeshield04
{
	meta:
		author = "PEiD"
		description = "EXE Shield 0.4 -> SMoKE"
		group = "116"
		function = "0"
	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D 81 ED BC 1A 40 00 EB 01 00 8D B5 46 1B 40 00 BA B2 0A 00 00 EB 01 00 8D 8D F8 25 40 00 8B 09 E8 14 00 00 00 83 EB 01 }
	condition:
		$a0 at pe.entry_point
}

rule exeshield37
{
	meta:
		author = "PEiD"
		description = "ExeShield 3.7 -> ExeShield Team"
		group = "444"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 CE 1E 42 AF F8 D6 CC E9 FB C8 4F 1B 22 7C B4 C8 0D BD 71 A9 C8 1F 5F B1 29 8F 11 73 8F 00 D1 88 87 A9 3F 4D 00 6C 3C BF C0 80 F7 AD 35 23 EB 84 82 6F 8C B9 0A FC EC E4 82 97 AE 0F 18 D2 47 1B 65 EA 46 A5 FD 3E 9D 75 2A 62 80 60 F9 B0 0D E1 AC 12 0E 9D 24 D5 43 CE 9A D6 18 BF 22 DA 1F 72 76 B0 98 5B C2 64 BC AE D8 }
	condition:
		$a0
}

rule exeshield_h
{
	meta:
		author = "PEiD"
		description = "EXE Shield 0.x [Heuristic] -> SMoKE"
		group = "116"
		function = "0"
	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D 81 ED ?? ?? 40 00 EB 01 00 8D B5 ?? ?? 40 00 BA ?? 0A 00 00 EB 01 00 8D 8D ?? ?? 40 00 8B 09 E8 14 00 00 00 83 EB 01 }
	condition:
		$a0 at pe.entry_point
}

rule exesmash
{
	meta:
		author = "PEiD"
		description = "ExeSmasher"
		group = "116"
		function = "0"
	strings:
		$a0 = { 9C FE 03 ?? 60 BE ?? ?? 41 ?? 8D BE ?? 10 FF FF 57 83 CD FF EB 10 }
	condition:
		$a0 at pe.entry_point
}

rule e32pack136
{
	meta:
		author = "PEiD"
		description = "EXE32Pack 1.36 -> SteelBytes"
		group = "118"
		function = "0"
	strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED CC 8D 40 }
	condition:
		$a0 at pe.entry_point
}

rule e32pack137
{
	meta:
		author = "PEiD"
		description = "EXE32Pack 1.37 -> SteelBytes"
		group = "118"
		function = "0"
	strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED 4C 8E 40 }
	condition:
		$a0 at pe.entry_point
}

rule e32pack138
{
	meta:
		author = "PEiD"
		description = "EXE32Pack 1.38 -> SteelBytes"
		group = "118"
		function = "0"
	strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED DC 8D 40 }
	condition:
		$a0 at pe.entry_point
}

rule e32pack139
{
	meta:
		author = "PEiD"
		description = "EXE32Pack 1.39 -> SteelBytes"
		group = "118"
		function = "0"
	strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED EC 8D 40 }
	condition:
		$a0 at pe.entry_point
}

rule e32pack13h
{
	meta:
		author = "PEiD"
		description = "EXE32Pack 1.3x -> SteelBytes"
		group = "118"
		function = "0"
	strings:
		$a0 = { 3B ?? 74 02 81 ?? 55 3B ?? 74 02 81 ?? 53 3B ?? 74 01 ?? ?? ?? ?? ?? 02 81 ?? ?? E8 ?? ?? ?? ?? 3B ?? 74 01 }
	condition:
		$a0 at pe.entry_point
}

rule ep1
{
	meta:
		author = "PEiD"
		description = "EP 1.0 -> CoDe_Inside"
		group = "117"
		function = "0"
	strings:
		$a0 = { 50 83 C0 17 8B F0 97 33 C0 33 C9 B1 24 AC }
	condition:
		$a0
}

rule ep2
{
	meta:
		author = "PEiD"
		description = "EP 2.0 -> CoDe_Inside"
		group = "117"
		function = "0"
	strings:
		$a0 = { 6A ?? 60 E9 01 01 }
	condition:
		$a0
}

rule eshield29f
{
	meta:
		author = "PEiD"
		description = "ExeShield Protector 2.9F -> www.exeshield.com"
		group = "119"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 0B 20 40 00 B9 EB 08 00 00 8D BD 53 20 40 00 8B F7 }
	condition:
		$a0 at pe.entry_point
}

rule estealth11
{
	meta:
		author = "PEiD"
		description = "EXEStealth 1.1 (y0da's Cryptor Clone) -> WebtoolMaster"
		group = "119"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED FB 1D 40 ?? B9 7B 09 00 00 8B F7 AC }
	condition:
		$a0 at pe.entry_point
}

/*
Clash with UPX ..
*/
rule estealth1x
{
	meta:
		author = "PEiD"
		description = "EXEStealth 1.x - 2.x -> WebtoolMaster"
		group = "119"
		function = "0"
	strings:
		$a0 = { E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 7B 09 00 00 8D BD ?? ?? ?? ??  8B F7 AC }
	condition:
		$a0 at pe.entry_point
}

rule estealth2
{
	meta:
		author = "PEiD"
		description = "EXEStealth 2.0 - 2.4 -> WebtoolMaster"
		group = "119"
		function = "7"
	strings:
		$a0 = { 60 BE 00 90 41 00 8D BE 00 80 FE FF 57 83 CD FF EB 10 }
	condition:
		$a0
}

rule exestealth275a
{
	meta:
		author = "PEiD"
		description = "EXEStealth 2.75a -> WebtoolMaster"
		group = "119"
		function = "0"
	strings:
		$a0 = { EB 58 53 68 61 72 65 77 61 72 65 2D 56 65 72 73 69 6F 6E 20 45 78 65 53 74 65 61 6C 74 68 2C 20 63 6F 6E 74 61 63 74 20 73 75 70 70 6F 72 74 40 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D }
	condition:
		$a0
}

rule execryptor13045
{
	meta:
		author = "PEiD"
		description = "EXECryptor 1.3.0.45 -> SoftLab MIL-TEC Ltd."
		group = "120"
		function = "0"
	strings:
		$a0 = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1 }
	condition:
		$a0 at pe.entry_point
}

rule execryptor151
{
	meta:
		author = "PEiD"
		description = "EXECryptor 1.5.1 -> SoftComplete Developement"
		group = "120"
		function = "0"
	strings:
		$a0 = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1 C1 ?? ?? ?? FE C3 31 C0 64 FF 30 64 89 20 CC C3 }
	condition:
		$a0 at pe.entry_point
}

rule execryptor1x
{
	meta:
		author = "PEiD"
		description = "EXECryptor 1.x.x -> SoftComplete Developement"
		group = "120"
		function = "0"
	strings:
		$a0 = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 }
	condition:
		$a0
}

rule execryptor239mp
{
	meta:
		author = "PEiD"
		description = "EXECryptor 2.3.9 (minimum protection) -> StrongBit"
		group = "2005"
		function = "0"
	strings:
		$a0 = { 68 ?? ?? ?? ?? E9 ?? ?? ?? FF 50 C1 C8 18 89 05 ?? ?? ?? ?? C3 C1 C0 18 51 E9 ?? ?? ?? FF 84 C0 0F 84 6A F9 FF FF E9 ?? ?? ?? FF C3 E9 ?? ?? ?? FF E8 CF E9 FF FF B8 01 00 00 00 E9 ?? ?? ?? FF 2B D0 68 A0 36 80 D4 59 81 C9 64 98 FF 99 E9 ?? ?? ?? FF 84 C0 0F 84 8E EC FF FF E9 ?? ?? ?? FF C3 87 3C 24 5F 8B 00 03 45 FC 83 C0 18 E9 ?? ?? ?? FF 87 0C 24 59 B8 01 00 00 00 D3 E0 23 D0 E9 02 18 00 00 0F 8D DB 00 00 00 C1 E8 14 E9 CA 00 00 00 9D 87 0C 24 59 87 1C 24 68 AE 73 B9 96 E9 C5 10 00 00 0F 8A ?? ?? ?? ?? E9 ?? ?? ?? FF 81 FD F5 FF 8F 07 E9 4F 10 00 00 C3 E9 5E 12 00 00 87 3C 24 E9 ?? ?? ?? FF E8 ?? ?? ?? FF 83 3D ?? ?? ?? ?? 00 0F 85 ?? ?? ?? ?? 8D 55 EC B8 ?? ?? ?? ?? E9 ?? ?? ?? FF E8 A7 1A 00 00 E8 2A CB FF FF E9 ?? ?? ?? FF C3 E9 ?? ?? ?? FF 59 89 45 E0 }
	condition:
		$a0
}

rule execryptor239mpdll
{
	meta:
		author = "PEiD"
		description = "EXECryptor 2.3.9 (minimum protection) DLL -> StrongBit"
		group = "2005"
		function = "0"
	strings:
		$a0 = { 51 68 ?? ?? ?? ?? 87 2C 24 8B CD 5D 81 E1 ?? ?? ?? ?? E9 ?? ?? ?? 00 89 45 F8 51 68 ?? ?? ?? ?? 59 81 F1 ?? ?? ?? ?? 0B 0D ?? ?? ?? ?? 81 E9 ?? ?? ?? ?? E9 ?? ?? ?? 00 81 C2 ?? ?? ?? ?? E8 ?? ?? ?? 00 87 0C 24 59 51 64 8B 05 30 00 00 00 8B 40 0C 8B 40 0C E9 ?? ?? ?? 00 F7 D6 2B D5 E9 ?? ?? ?? 00 87 3C 24 8B CF 5F 87 14 24 1B CA E9 ?? ?? ?? 00 83 C4 08 68 ?? ?? ?? ?? E9 ?? ?? ?? 00 C3 E9 ?? ?? ?? 00 E9 ?? ?? ?? 00 50 8B C5 87 04 24 8B EC 51 0F 88 ?? ?? ?? 00 FF 05 ?? ?? ?? ?? E9 ?? ?? ?? 00 87 0C 24 59 99 03 04 24 E9 ?? ?? ?? 00 C3 81 D5 ?? ?? ?? ?? 9C E9 ?? ?? ?? 00 81 FA ?? ?? ?? ?? E9 ?? ?? ?? 00 C1 C3 15 81 CB ?? ?? ?? ?? 81 F3 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? 87 }
	condition:
		$a0
}

rule execryptor239comp
{
	meta:
		author = "PEiD"
		description = "EXECryptor 2.3.9 (compressed resources) -> StrongBit"
		group = "2005"
		function = "0"
	strings:
		$a0 = { 51 68 ?? ?? ?? ?? 59 81 F1 12 3C CB 98 E9 53 2C 00 00 F7 D7 E9 EB 60 00 00 83 45 F8 02 E9 E3 36 00 00 F6 45 F8 20 0F 84 1E 21 00 00 55 E9 80 62 00 00 87 0C 24 8B E9 ?? ?? ?? ?? 00 00 23 C1 81 E9 ?? ?? ?? ?? 57 E9 ED 00 00 00 0F 88 ?? ?? ?? ?? E9 2C 0D 00 00 81 ED BB 43 CB 79 C1 E0 1C E9 9E 14 00 00 0B 15 ?? ?? ?? ?? 81 E2 2A 70 7F 49 81 C2 9D 83 12 3B E8 0C 50 00 00 E9 A0 16 00 00 59 5B C3 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 E8 41 42 00 00 E9 93 33 00 00 31 DB 89 D8 59 5B C3 A1 ?? ?? ?? ?? 8A 00 2C 99 E9 82 30 00 00 0F 8A ?? ?? ?? ?? B8 01 00 00 00 31 D2 0F A2 25 FF 0F 00 00 E9 72 21 00 00 0F 86 57 0B 00 00 E9 ?? ?? ?? ?? C1 C0 03 E8 F0 36 00 00 E9 41 0A 00 00 81 F7 B3 6E 85 EA 81 C7 ?? ?? ?? ?? 87 3C 24 E9 74 52 00 00 0F 8E ?? ?? ?? ?? E8 5E 37 00 00 68 B1 74 96 13 5A E9 A1 04 00 00 81 D1 49 C0 12 27 E9 50 4E 00 00 C1 C8 1B 1B C3 81 E1 96 36 E5 }
	condition:
		$a0
}

rule execryptor239compdll
{
	meta:
		author = "PEiD"
		description = "EXECryptor 2.3.9 (compressed resources) DLL -> StrongBit"
		group = "2005"
		function = "0"
	strings:
		$a0 = { 50 68 ?? ?? ?? ?? 58 C1 C0 0F E9 ?? ?? ?? 00 87 04 24 58 89 45 FC E9 ?? ?? ?? FF FF 05 ?? ?? ?? ?? E9 ?? ?? ?? 00 C1 C3 18 E9 ?? ?? ?? ?? 8B 55 08 09 42 F8 E9 ?? ?? ?? FF 83 7D F0 01 0F 85 ?? ?? ?? ?? E9 ?? ?? ?? 00 87 34 24 5E 8B 45 FC 33 D2 56 8B F2 E9 ?? ?? ?? 00 BA ?? ?? ?? ?? E8 ?? ?? ?? 00 A3 ?? ?? ?? ?? C3 E9 ?? ?? ?? 00 C3 83 C4 04 C3 E9 ?? ?? ?? FF 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 E8 ?? ?? ?? 00 E9 ?? ?? ?? FF C1 C2 03 81 CA ?? ?? ?? ?? 81 C2 ?? ?? ?? ?? 03 C2 5A E9 ?? ?? ?? FF 81 E7 ?? ?? ?? ?? 81 EF ?? ?? ?? ?? 81 C7 ?? ?? ?? ?? 89 07 E9 ?? ?? ?? ?? 0F 89 ?? ?? ?? ?? 87 14 24 5A 50 C1 C8 10 }
	condition:
		$a0
}

rule execryptor226mp
{
	meta:
		author = "PEiD"
		description = "EXECryptor 2.2.6 (minimum protection) -> StrongBit"
		group = "2005"
		function = "0"
	strings:
		$a0 = { 50 68 ?? ?? ?? ?? 58 81 E0 ?? ?? ?? ?? E9 ?? ?? ?? 00 87 0C 24 59 E8 ?? ?? ?? 00 89 45 F8 E9 ?? ?? ?? ?? 0F 83 ?? ?? ?? 00 E9 ?? ?? ?? ?? 87 14 24 5A 57 68 ?? ?? ?? ?? E9 ?? ?? ?? ?? 58 81 C0 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? 81 C8 ?? ?? ?? ?? 81 E0 ?? ?? ?? ?? E9 ?? ?? ?? 00 C3 E9 ?? ?? ?? ?? C3 BF ?? ?? ?? ?? 81 CB ?? ?? ?? ?? BA ?? ?? ?? ?? 52 E9 ?? ?? ?? 00 E8 ?? ?? ?? 00 E9 ?? ?? ?? 00 E9 ?? ?? ?? ?? 87 34 24 5E 66 8B 00 66 25 ?? ?? E9 ?? ?? ?? ?? 8B CD 87 0C 24 8B EC 51 89 EC 5D 8B 05 ?? ?? ?? ?? 09 C0 E9 ?? ?? ?? ?? 59 81 C1 ?? ?? ?? ?? C1 C1 ?? 23 0D ?? ?? ?? ?? 81 F9 ?? ?? ?? ?? E9 ?? ?? ?? ?? C3 E9 ?? ?? ?? 00 13 D0 0B F9 E9 ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 8B 64 24 08 31 C0 64 8F 05 00 00 00 00 5A E9 ?? ?? ?? ?? 3C A4 0F 85 ?? ?? ?? 00 8B 45 FC 66 81 38 ?? ?? 0F 84 05 00 00 00 E9 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? E9 ?? ?? ?? ?? 87 3C 24 5F 31 DB 31 C9 31 D2 68 ?? ?? ?? ?? E9 ?? ?? ?? ?? 89 45 FC 33 C0 89 45 F4 83 7D FC 00 E9 ?? ?? ?? ?? 53 52 8B D1 87 14 24 81 C0 ?? ?? ?? ?? 0F 88 ?? ?? ?? ?? 3B CB }
	condition:
		$a0
}

rule execryptor226mpdll
{
	meta:
		author = "PEiD"
		description = "EXECryptor 2.2.6 (minimum protection) DLL -> StrongBit"
		group = "2005"
		function = "0"
	strings:
		$a0 = { 50 8B C6 87 04 24 68 ?? ?? ?? ?? 5E E9 ?? ?? ?? ?? 85 C8 E9 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? 0F 81 ?? ?? ?? 00 81 FA ?? ?? ?? ?? 33 D0 E9 ?? ?? ?? 00 0F 8D ?? ?? ?? 00 81 D5 ?? ?? ?? ?? F7 D1 0B 15 ?? ?? ?? ?? C1 C2 ?? 81 C2 ?? ?? ?? ?? 9D E9 ?? ?? ?? ?? C1 E2 ?? C1 E8 ?? 81 EA ?? ?? ?? ?? 13 DA 81 E9 ?? ?? ?? ?? 87 04 24 8B C8 E9 ?? ?? ?? ?? 55 8B EC 83 C4 F8 89 45 FC 8B 45 FC 89 45 F8 8B 45 08 E9 ?? ?? ?? ?? 8B 45 E0 C6 00 00 FF 45 E4 E9 ?? ?? ?? ?? FF 45 E4 E9 ?? ?? ?? 00 F7 D3 0F 81 ?? ?? ?? ?? E9 ?? ?? ?? ?? 87 34 24 5E 8B 45 F4 E8 ?? ?? ?? 00 8B 45 F4 8B E5 5D C3 E9 3B CB }
	condition:
		$a0
}

rule exejoiner
{
	meta:
		author = "PEiD"
		description = "EXEJoiner 1.0 -> y0da"
		group = "304"
		function = "0"
	strings:
		$a0 = { 68 ?? 10 40 ?? 68 04 01 ?? ?? E8 39 03 ?? ?? 05 ?? 10 40 C6 ?? 5C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? E8 }
	condition:
		$a0
}

rule expressor
{
	meta:
		author = "PEiD"
		description = "eXPressor 1.3.0 -> CGSoftLabs"
		group = "304"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 EC ?? 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E ?? 2E 2E B8 ?? ?? ?? 00 2B 05 ?? ?? ?? 00 A3 ?? ?? ?? 00 83 3D ?? ?? ?? 00 00 74 13 A1 ?? ?? ?? 00 03 05 ?? ?? ?? 00 89 45 C8 E9 ?? 06 00 00 C7 05 ?? ?? ?? 00 01 00 00 00 83 7D 0C 01 74 04 83 65 08 00 6A 04 68 00 10 00 00 68 04 01 00 00 6A 00 FF 15 ?? ?? ?? 00 89 45 EC 68 04 01 00 00 FF 75 EC FF 75 08 FF 15 ?? ?? ?? 00 8B 4D EC 8D 44 01 FF 89 45 ?? 8B 45 ?? 0F BE 00 83 F8 5C 74 09 8B 45 ?? 48 89 45 ?? EB EC 8B 45 ?? 40 89 45 ?? 8B 45 ?? 2B 45 EC 89 45 ?? 6A 04 68 00 10 00 00 68 04 01 00 00 6A 00 FF 15 ?? ?? ?? 00 89 45 FC 8B 4D ?? 8B 75 EC 8B 7D FC 8B C1 C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 45 FC 03 45 }
	condition:
		$a0
}

rule expressor150x
{
	meta:
		author = "PEiD"
		description = "eXPressor 1.5.0.x -> CGSoftLabs"
		group = "2006"
		function = "0"
	strings:
		$a0 = { 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 83 A5 ?? ?? ?? ?? ?? F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 35 2E 00 83 7D 0C ?? 75 23 8B 45 08 A3 ?? ?? ?? ?? 6A 04 68 00 10 00 00 68 20 03 00 00 6A 00 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? EB 04 }
	condition:
		$a0
}

rule ezip1
{
	meta:
		author = "PEiD"
		description = "EZIP 1.0 -> Jonathan Clark"
		group = "121"
		function = "0"
	strings:
		$a0 = { E9 19 32 ?? ?? E9 7C 2A ?? ?? E9 19 24 ?? ?? E9 FF 23 ?? ?? E9 1E 2E ?? ?? E9 88 2E ?? ?? E9 2C }
	condition:
		$a0 at pe.entry_point
}

rule farbrausch
{
	meta:
		author = "PEiD"
		description = "UPX Modified Stub -> Farb-rausch Consumer Consulting"
		group = "122"
		function = "0"
	strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF FC B2 80 A4 E8 }
	condition:
		$a0 at pe.entry_point
}

rule flash4
{
	meta:
		author = "PEiD"
		description = "Flash Projector/Player 4.0 -> Macromedia Inc."
		group = "22"
		function = "0"
	strings:
		$a0 = { 83 EC 44 56 FF 15 24 41 43 ?? 8B F0 8A 06 3C 22 75 1C 8A 46 01 }
	condition:
		$a0 at pe.entry_point
}

rule flash5
{
	meta:
		author = "PEiD"
		description = "Flash Projector/Player 5.0 -> Macromedia Inc."
		group = "22"
		function = "0"
	strings:
		$a0 = { 83 EC 44 56 FF 15 70 61 44 ?? 8B F0 8A 06 3C 22 75 1C 8A 46 01 }
	condition:
		$a0 at pe.entry_point
}

rule flash6
{
	meta:
		author = "PEiD"
		description = "Flash Projector/Player 6.0 -> Macromedia Inc."
		group = "22"
		function = "0"
	strings:
		$a0 = { 83 EC 44 56 FF 15 24 81 49 ?? 8B F0 8A 06 3C 22 75 1C 8A 46 01 }
	condition:
		$a0 at pe.entry_point
}

rule french181
{
	meta:
		author = "PEiD"
		description = "French Layor 1.81 -> Dr. rED mEAT"
		group = "123"
		function = "0"
	strings:
		$a0 = { EB 01 60 E8 00 00 00 00 5D 81 ED 08 10 40 00 E8 61 00 00 00 6A 00 FF 95 17 12 40 00 89 85 D3 11 40 00 8D 85 00 10 40 00 80 70 35 5C 66 81 B0 6A 00 00 00 7B 91 }
	condition:
		$a0 at pe.entry_point
}

rule realbasic
{
	meta:
		author = "PEiD"
		description = "REALBasic"
		group = "555"
		function = "0"
	strings:
		$a0 = { 55 89 E5 6A FF 68 78 FC 58 00 68 50 D9 53 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 50 53 83 }
	condition:
		$a0
}

rule realbasicold
{
	meta:
		author = "PEiD"
		description = "REALBasic"
		group = "555"
		function = "0"
	strings:
		$a0 = { 55 89 E5 53 83 EC 48 55 B8 FF FF FF FF 50 50 68 C0 A0 4B 00 64 FF 35 00 00 00 00 64 89 25 00 00 }
	condition:
		$a0
}

rule realbasicplug
{
	meta:
		author = "PEiD"
		description = "REALBasic internal plugin"
		group = "555"
		function = "0"
	strings:
		$a0 = { 55 89 E5 53 56 8B 75 0C 85 F6 57 8B 5D 10 B8 01 00 00 00 75 1B 83 3D 28 C2 00 10 00 75 12 8D 65 }
	condition:
		$a0
}

rule fsg1
{
	meta:
		author = "PEiD"
		description = "FSG 1.0 -> dulek/xt"
		group = "123"
		function = "0"
	strings:
		$a0 = { BB D0 01 40 ?? BF ?? 10 40 ?? BE ?? ?? ?? ?? 53 E8 0A ?? ?? ?? 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B }
	condition:
		$a0 at pe.entry_point
}

rule fsg11
{
	meta:
		author = "PEiD"
		description = "FSG 1.1 / private -> dulek/xt"
		group = "123"
		function = "8"
	strings:
		$a0 = { BB D0 01 40 ?? BF ?? 10 40 ?? BE ?? ?? ?? ?? FC B2 80 8A 06 46 88 07 47 02 D2 75 05 8A 16 }
	condition:
		$a0 at pe.entry_point
}

rule fsg12h1
{
	meta:
		author = "PEiD"
		description = "FSG 1.2 -> dulek/xt"
		group = "123"
		function = "9"
	strings:
		$a0 = { 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C ?? ?? 4C 6F 61 64 4C 69 62 72 61 72 79 41 ?? ?? 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 }
	condition:
		$a0 at pe.entry_point
}

rule fsg131
{
	meta:
		author = "PEiD"
		description = "FSG 1.31 -> dulek/xt"
		group = "123"
		function = "0"
	strings:
		$a0 = { BB D0 01 40 ?? BF ?? 10 40 ?? BE ?? ?? ?? ?? 53 BB ?? ?? ?? ?? B2 80 A4 B6 80 FF D3 }
	condition:
		$a0 at pe.entry_point
}

rule fsg133
{
	meta:
		author = "PEiD"
		description = "FSG 1.33 -> dulek/xt"
		group = "123"
		function = "0"
	strings:
		$a0 = { BE ?? ?? ?? ?? AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3C }
	condition:
		$a0
}

rule fsg133a
{
	meta:
		author = "PEiD"
		description = "FSG 1.33a -> dulek/xt"
		group = "123"
		function = "0"
	strings:
		$a0 = { BE ?? ?? ?? ?? AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3A }
	condition:
		$a0
}

rule fsg13
{
	meta:
		author = "PEiD"
		description = "FSG 1.3 -> dulek/xt"
		group = "123"
		function = "10"
	strings:
		$a0 = { 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C ?? ?? ?? 4C 6F 61 64 4C 69 62 72 61 72 79 41 ?? ?? 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 }
	condition:
		$a0 at pe.entry_point
}

rule fsg13x
{
	meta:
		author = "PEiD"
		description = "FSG 1.3x -> dulek/xt"
		group = "123"
		function = "11"
	strings:
		$a0 = { E0 ?? ?? C0 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C ?? ?? ?? 4C 6F 61 64 4C 69 62 72 61 72 79 41 ?? ?? 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 }
	condition:
		$a0 at pe.entry_point
}

rule fsg2
{
	meta:
		author = "PEiD"
		description = "FSG 2.0 -> bart/xt"
		group = "123"
		function = "0"
	strings:
		$a0 = { 87 25 ?? ?? ?? ?? 61 94 55 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3A AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 24 }
	condition:
		$a0 at pe.entry_point
}

rule fsgcryptnew
{
	meta:
		author = "PEiD"
		description = "FSG Crypt 0.2 (Private) -> EMBRACE"
		group = "123"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? B9 00 00 00 00 80 34 08 ?? B8 ?? ?? ?? ?? B9 0B 00 00 00 80 34 08 ?? E2 }
	condition:
		$a0
}

rule fsgcrypt
{
	meta:
		author = "PEiD"
		description = "FSG Crypt 0.1 (Private) -> EMBRACE"
		group = "123"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? B9 0B 00 00 00 80 34 08 ?? E2 }
	condition:
		$a0
}

rule gm11
{
	meta:
		author = "PEiD"
		description = "Goat's PE Mutilator 1.1"
		group = "124"
		function = "0"
	strings:
		$a0 = { E8 EB 0B 00 00 00 00 00 }
	condition:
		$a0
}

rule gm12
{
	meta:
		author = "PEiD"
		description = "Goat's PE Mutilator 1.2"
		group = "124"
		function = "0"
	strings:
		$a0 = { E8 E9 0B 00 00 00 00 00 }
	condition:
		$a0
}

rule gm16
{
	meta:
		author = "PEiD"
		description = "Goat's PE Mutilator 1.6"
		group = "999"
		function = "0"
	strings:
		$a0 = { E8 EA 0B 00 00 ?? ?? ?? 8B 1C 79 F6 63 D8 8D 22 B0 BF F6 49 08 C3 02 BD 3B 6C 29 46 13 28 5D }
	condition:
		$a0
}

rule ghfprot
{
	meta:
		author = "PEiD"
		description = "GHF Protector (packed) -> GPcH"
		group = "999"
		function = "0"
	strings:
		$a0 = { 60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 68 ?? ?? ?? ?? 50 B8 ?? ?? ?? ?? FF 10 68 00 00 00 00 6A 40 FF D0 89 05 ?? ?? ?? ?? 89 C7 BE ?? ?? ?? ?? 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 89 E8 B3 01 56 89 FE 29 C6 F3 A4 5E EB 8E 00 D2 75 05 }
	condition:
		$a0
}

rule hidepe
{
	meta:
		author = "PEiD"
		description = "Hide PE 1.0 -> BGCorp"
		group = "124"
		function = "0"
	strings:
		$a0 = { BA ?? ?? ?? ?? B8 ?? ?? ?? ?? 89 02 83 C2 04 B8 ?? ?? ?? ?? 89 02 83 C2 04 B8 ?? ?? ?? ?? 89 02 83 C2 F8 FF E2 }
	condition:
		$a0 at pe.entry_point
}

rule hyperlock
{
	meta:
		author = "PEiD"
		description = "Hyper Lock -> Guven Bilgisayar Ltd."
		group = "124"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 02 00 00 EB 59 5B E8 00 00 00 00 5F 81 EF 06 00 00 00 33 C0 8B F1 D1 E9 D1 E9 49 55 51 83 EE 04 D1 C2 31 14 33 03 04 33 33 D0 59 8B EC 03 55 FC E8 00 00 00 00 5D }
	condition:
		$a0
}

rule inno_h
{
	meta:
		author = "PEiD"
		description = "Inno-Setup Module"
		group = "305"
		function = "0"
	strings:
		$a0 = { 49 6E 6E 6F 53 65 74 75 70 4C 64 72 57 69 6E 64 6F 77 ?? ?? 53 54 41 54 49 43 }
	condition:
		$a0 at pe.entry_point
}

rule istub32
{
	meta:
		author = "PEiD"
		description = "Install Stub 32-bit -> InstallShield"
		group = "301"
		function = "0"
	strings:
		$a0 = { 55 8B EC 81 EC 14 ?? ?? ?? 53 56 57 6A ?? FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 74 29 }
	condition:
		$a0 at pe.entry_point
}

rule istub32_gbls
{
	meta:
		author = "PEiD"
		description = "GLBS Install Stub 32-bit -> Wise"
		group = "306"
		function = "12"
	strings:
		$a0 = { 55 8B EC 81 EC ?? ?? ?? ?? 53 56 }
	condition:
		$a0
}

rule instany61
{
	meta:
		author = "PEiD"
		description = "InstallAnywhere 6.1"
		group = "999"
		function = "0"
	strings:
		$a0 = { 60 BE 00 A0 42 00 8D BE 00 70 FD FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 75 20 41 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 }
	condition:
		$a0
}

rule jdpack
{
	meta:
		author = "PEiD"
		description = "JDPack 1.x / JDProtect 0.9 -> TLZJ18 Software"
		group = "125"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 8B D5 81 ED ?? ?? ?? ?? 2B 95 ?? ?? ?? ?? 81 EA 06 ?? ?? ?? 89 95 ?? ?? ?? ?? 83 BD }
	condition:
		$a0 at pe.entry_point
}

rule jibzap
{
	meta:
		author = "PEiD"
		description = "APatch GUI 1.x -> Joergen Ibsen"
		group = "126"
		function = "0"
	strings:
		$a0 = { 52 31 C0 E8 FF FF FF FF }
	condition:
		$a0
}

rule kgcrypt
{
	meta:
		author = "PEiD"
		description = "KGCrypt 0.x -> Uradox/LUCiD"
		group = "127"
		function = "0"
	strings:
		$a0 = { E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 64 A1 30 ?? ?? ?? 84 C0 74 ?? 64 A1 20 ?? ?? ?? 0B C0 74 }
	condition:
		$a0
}

rule kryptor3
{
	meta:
		author = "PEiD"
		description = "k.kryptor 3 -> r!sc"
		group = "128"
		function = "0"
	strings:
		$a0 = { EB 66 87 DB }
	condition:
		$a0
}

rule kryptor5
{
	meta:
		author = "PEiD"
		description = "k.kryptor 5 -> r!sc"
		group = "128"
		function = "0"
	strings:
		$a0 = { E8 03 ?? ?? ?? E9 EB 6C 58 40 FF E0 }
	condition:
		$a0
}

rule kryptor6
{
	meta:
		author = "PEiD"
		description = "k.kryptor 6 -> r!sc"
		group = "128"
		function = "0"
	strings:
		$a0 = { E8 03 ?? ?? ?? E9 EB 68 58 33 D2 74 02 E9 E9 40 42 75 02 }
	condition:
		$a0
}

rule kryptor8
{
	meta:
		author = "PEiD"
		description = "k.kryptor 8 -> r!sc & noodlespa"
		group = "128"
		function = "0"
	strings:
		$a0 = { EB 6A 87 DB }
	condition:
		$a0
}

rule kryptor9a
{
	meta:
		author = "PEiD"
		description = "k.kryptor 9 / kryptor a -> r!sc & noodlespa"
		group = "128"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5E B9 ?? ?? ?? ?? 2B C0 02 04 0E D3 C0 49 79 F8 41 8D 7E 2C 33 46 ?? 66 B9 }
	condition:
		$a0 at pe.entry_point
}

rule krypton02
{
	meta:
		author = "PEiD"
		description = "Krypton 0.2 -> Yado/Lockless"
		group = "129"
		function = "0"
	strings:
		$a0 = { 8B 0C 24 E9 0A 7C 01 ?? AD 42 40 BD BE 9D 7A 04 }
	condition:
		$a0 at pe.entry_point
}

rule krypton03
{
	meta:
		author = "PEiD"
		description = "Krypton 0.3 -> Yado/Lockless"
		group = "129"
		function = "0"
	strings:
		$a0 = { 8B 0C 24 E9 C0 8D 01 ?? C1 3A 6E CA 5D 7E 79 6D B3 64 5A 71 EA }
	condition:
		$a0 at pe.entry_point
}

rule krypton04
{
	meta:
		author = "PEiD"
		description = "Krypton 0.4 -> Yado/Lockless"
		group = "129"
		function = "0"
	strings:
		$a0 = { 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED 61 34 ?? ?? 2B 85 60 37 ?? ?? 83 E8 06 }
	condition:
		$a0 at pe.entry_point
}

rule krypton05
{
	meta:
		author = "PEiD"
		description = "Krypton 0.5 -> Yado/Lockless"
		group = "129"
		function = "0"
	strings:
		$a0 = { 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED 71 44 ?? ?? 2B 85 64 60 ?? ?? EB 43 DF }
	condition:
		$a0 at pe.entry_point
}

rule lamecrypt
{
	meta:
		author = "PEiD"
		description = "LameCrypt -> LaZaRus"
		group = "130"
		function = "0"
	strings:
		$a0 = { 60 66 9C BB ?? ?? ?? ?? 80 B3 ?? 10 40 ?? 90 4B 83 FB FF 75 F3 66 9D 06 }
	condition:
		$a0 at pe.entry_point
}

rule kkrunchy
{
	meta:
		author = "PEiD"
		description = "kkrunchy -> Ryd"
		group = "999"
		function = "0"
	strings:
		$a0 = { BD 08 ?? ?? 00 C7 45 00 ?? ?? ?? 00 FF 4D 08 C6 45 0C 05 8D 7D 14 31 C0 B4 04 89 C1 F3 AB BF ?? ?? ?? 00 57 BE ?? ?? ?? 00 31 C9 41 FF 4D 0C 8D 9C 8D A0 00 00 00 FF D6 10 C9 73 F3 FF 45 0C 91 AA 83 C9 FF 8D 5C 8D 18 FF D6 74 DD E3 17 8D 5D 1C FF D6 74 10 8D 9D A0 08 00 00 E8 EB 00 00 00 8B 45 10 EB 42 8D 9D A0 04 00 00 E8 DB 00 00 00 49 49 78 40 8D 5D 20 74 03 83 C3 40 31 D2 42 E8 BD 00 00 00 8D 0C 48 F6 C2 10 74 F3 41 91 8D 9D A0 08 00 00 E8 B2 00 00 00 3D 00 08 00 00 83 D9 FF 83 F8 60 83 D9 FF 89 45 10 56 89 FE 29 C6 F3 A4 5E EB 90 BE ?? ?? ?? 00 BB ?? ?? ?? 00 55 46 AD 85 C0 74 29 97 56 FF 13 85 C0 74 16 95 AC 84 C0 75 FB 38 06 74 E8 78 0D 56 55 FF 53 04 AB 85 C0 }
	condition:
		$a0
}

rule lockless
{
	meta:
		author = "PEiD"
		description = "Lockless Intro Packer [Krypton Mod.] -> Yado"
		group = "129"
		function = "0"
	strings:
		$a0 = { 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED F6 73 ?? ?? 2B 85 ?? ?? ?? ?? 83 E8 06 89 85 }
	condition:
		$a0 at pe.entry_point
}

rule mew01
{
	meta:
		author = "PEiD"
		description = "MEW 5 0.1 beta -> NorthFox/HCC"
		group = "444"
		function = "0"
	strings:
		$a0 = { BE 5B 00 40 00 AD 91 AD 93 53 AD 96 56 5F AC C0 C0 ?? 04 ?? C0 C8 ?? AA E2 F4 C3 ?? ?? 01 00 ?? ?? ?? 00 00 10 40 00 }
	condition:
		$a0
}

rule mew10
{
	meta:
		author = "PEiD"
		description = "MEW 10 1.0 -> NorthFox/HCC"
		group = "444"
		function = "14"
	strings:
		$a0 = { 33 C0 E9 ?? ?? ?? FF }
	condition:
		$a0
}

rule msupdt
{
	meta:
		author = "PEiD"
		description = "Microsoft Update Stub CAB SFX"
		group = "23"
		function = "0"
	strings:
		$a0 = { 81 EC 88 ?? ?? ?? 53 56 57 6A FF 33 DB BE ?? ?? ?? 80 68 ?? ?? ?? ?? 89 5C 24 ?? 89 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 FF 47 89 3D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 }
	condition:
		$a0 at pe.entry_point
}

rule mslrh01
{
	meta:
		author = "PEiD"
		description = "[MSLRH] 0.1 -> emadicius"
		group = "999"
		function = "0"
	strings:
		$a0 = { 60 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 }
	condition:
		$a0 at pe.entry_point
}

rule neolite1x
{
	meta:
		author = "PEiD"
		description = "Neolite 1.0 - 1.01 -> Neoworx Inc."
		group = "130"
		function = "0"
	strings:
		$a0 = { 8B 44 24 04 8D 54 24 FC 23 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 50 FF 25 }
	condition:
		$a0 at pe.entry_point
}

rule neolite2x
{
	meta:
		author = "PEiD"
		description = "Neolite 2.0 / 2.x -> Neoworx Inc."
		group = "130"
		function = "0"
	strings:
		$a0 = { 8B 44 24 04 23 05 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 04 FE 05 ?? ?? ?? ?? 0B C0 74 }
	condition:
		$a0 at pe.entry_point
}

rule nfo1
{
	meta:
		author = "PEiD"
		description = "NFO 1.0 -> bart/CrackPL"
		group = "131"
		function = "0"
	strings:
		$a0 = { 60 9C 8D 50 12 2B C9 B1 1E 8A 02 34 ?? 88 02 42 E2 F7 }
	condition:
		$a0
}

rule nfo_h
{
	meta:
		author = "PEiD"
		description = "NFO 1.x modified -> bart/CrackPL"
		group = "131"
		function = "0"
	strings:
		$a0 = { 60 9C 8D 50 }
	condition:
		$a0
}

rule noodle2
{
	meta:
		author = "PEiD"
		description = "NoodleCrypt 2.0 -> noodlespa"
		group = "132"
		function = "0"
	strings:
		$a0 = { EB 01 9A E8 3D ?? ?? ?? EB 01 9A E8 EB 01 ?? ?? EB 01 9A E8 2C 04 ?? ?? EB 01 }
	condition:
		$a0 at pe.entry_point
}

rule nspack13
{
	meta:
		author = "PEiD"
		description = "nSPack 1.3 -> North Star/Liu Xing Ping"
		group = "444"
		function = "0"
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 ?? ?? FF FF 8B 06 83 F8 00 74 11 8D B5 ?? ?? FF FF 8B 06 83 F8 01 0F 84 F1 01 }
	condition:
		$a0 at pe.entry_point
}

rule nspack22
{
	meta:
		author = "PEiD"
		description = "nSPack 2.2 -> North Star/Liu Xing Ping"
		group = "444"
		function = "0"
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 8B 06 83 F8 00 74 11 8D B5 ?? ?? FF FF 8B 06 83 F8 01 0F 84 4B 02 00 00 }
	condition:
		$a0 at pe.entry_point
}

rule nspack21_25
{
	meta:
		author = "PEiD"
		description = "nSPack 2.1 - 2.5 -> North Star/Liu Xing Ping"
		group = "555"
		function = "0"
	strings:
		$a0 = { 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 5D C2 08 00 6A 00 FF 95 ?? ?? ?? ?? C3 8B 00 11 3B 51 04 75 0A C7 41 38 10 01 60 02 0C FF C3 8A 0E 02 42 89 11 C0 8B 44 24 04 83 38 61 10 67 08 0C 06 56 20 3C 03 D0 83 49 08 FF 6A 05 D6 58 1E 5E E8 C9 73 02 8B C8 0C 0F B6 00 C0 C1 E2 08 0B C2 4E 89 7C 41 1E 75 EA 5E 1C 04 00 53 56 8B 71 08 33 0F DB 85 D2 57 00 }
	condition:
		$a0 at pe.entry_point
}

rule nspack21_25_net
{
	meta:
		author = "PEiD"
		description = "nSPack 2.1 - 2.5 (.NET) -> North Star/Liu Xing Ping"
		group = "555"
		function = "0"
	strings:
		$a0 = { 8D 9C 1B 6C 0E 00 00 53 52 FF 55 10 FF 77 09 89 45 F4 FF 75 0C FF 77 05 FF 75 F8 FF 75 FC FF 75 08 56 53 50 E8 FE FB FF FF 83 C4 24 33 F6 85 C0 75 01 46 68 00 80 00 00 6A 00 FF 75 F4 FF 55 14 8B C6 5E 5B 5F C9 C3 B8 ?? ?? ?? ?? C3 83 7C 24 04 00 75 03 33 C0 C3 A1 6C 70 00 30 A3 70 5B 00 30 8B 0D 34 70 00 30 51 50 FF 74 24 0C 89 0D 6C 5B 00 30 68 ?? ?? ?? ?? E8 12 FF FF FF 83 C4 10 F7 D8 1B C0 F7 D8 C3 }
	condition:
		$a0 at pe.entry_point
}

rule nspack31
{
	meta:
		author = "PEiD"
		description = "nSPack 3.1 -> North Star/Liu Xing Ping"
		group = "444"
		function = "0"
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? FF FF 8A 03 3C 00 74 10 8D 9D ?? ?? FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 01 13 8B 33 03 7B 04 57 51 52 53 FF B5 ?? ?? FF FF FF B5 ?? ?? FF FF 8B D6 8B CF 8B 85 ?? ?? FF FF 05 AA 05 00 00 FF D0 5B 5A 59 5F 83 F9 00 74 05 83 C3 08 EB C5 68 00 80 00 00 6A 00 }
	condition:
		$a0
}

rule ntkrnl
{
	meta:
		author = "PEiD"
		description = "NTKrnl Security Suite -> NTKrnl Team"
		group = "133"
		function = "18"
	strings:
		$a0 = { 68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 }
	condition:
		$a0
}

rule nullsoft13
{
	meta:
		author = "PEiD"
		description = "Nullsoft PiMP 1.3x"
		group = "24"
		function = "0"
	strings:
		$a0 = { 55 8B EC 81 EC ?? ?? ?? ?? 56 57 6A ?? BE ?? ?? ?? ?? 59 8D BD }
	condition:
		$a0 at pe.entry_point
}

rule nullsoft14
{
	meta:
		author = "PEiD"
		description = "Nullsoft PiMP 1.x"
		group = "24"
		function = "0"
	strings:
		$a0 = { 83 EC 5C 53 55 56 57 FF 15 }
	condition:
		$a0 at pe.entry_point
}

rule nullsoft_h
{
	meta:
		author = "PEiD"
		description = "Nullsoft PiMP stub 1.x"
		group = "24"
		function = "0"
	strings:
		$a0 = { C3 83 EC ?? 53 56 57 FF 15 }
	condition:
		$a0 at pe.entry_point
}

rule nullsoft_stub_h
{
	meta:
		author = "PEiD"
		description = "Nullsoft PiMP stub"
		group = "24"
		function = "19"
	strings:
		$a0 = { 83 EC ?? 53 55 56 57 FF 15 ?? ?? 40 }
	condition:
		$a0
}

rule nullsoft2_h
{
	meta:
		author = "PEiD"
		description = "Nullsoft PiMP 2.x stub"
		group = "24"
		function = "0"
	strings:
		$a0 = { 49 6E 73 74 61 6C 6C 65 72 20 63 6F 72 72 75 70 74 65 64 20 6F 72 20 69 6E 63 6F 6D 70 6C 65 74 65 2E 0D 0A 0D 0A 54 68 69 73 20 63 6F 75 6C 64 20 62 65 20 74 68 65 20 72 65 73 75 6C 74 20 6F 66 20 61 20 66 61 69 6C 65 64 20 64 6F 77 6E 6C 6F 61 64 20 6F 72 20 63 6F 72 72 75 70 74 69 6F 6E 20 66 72 6F 6D 20 61 20 76 69 72 75 73 2E 0D 0A 0D 0A 49 66 20 64 65 73 70 65 72 61 74 65 2C 20 74 72 79 20 74 68 65 20 2F 4E 43 52 43 20 63 6F 6D 6D 61 6E 64 20 6C 69 6E 65 20 73 77 69 74 63 68 20 28 4E 4F 54 20 72 65 63 6F 6D 6D 65 6E 64 65 64 29 }
	condition:
		$a0 at pe.entry_point
}

rule packman10
{
	meta:
		author = "PEiD"
		description = "Packanoid 1.0 -> Arkanoid"
		group = "444"
		function = "0"
	strings:
		$a0 = { BF 00 10 40 00 BE ?? ?? ?? 00 E8 9D 00 00 00 B8 ?? ?? ?? 00 8B 30 8B 78 04 BB ?? ?? 41 00 8B 43 04 91 E3 1F 51 FF D6 56 96 8B 13 8B 02 91 E3 0D 52 51 56 FF D7 5A 89 02 83 C2 04 EB EE 83 C3 08 }
	condition:
		$a0
}

rule packman11
{
	meta:
		author = "PEiD"
		description = "Packanoid 1.1 -> Arkanoid"
		group = "444"
		function = "0"
	strings:
		$a0 = { B8 64 00 40 00 50 50 8B 70 9E 8B 78 60 B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 }
	condition:
		$a0
}

rule pmaster16
{
	meta:
		author = "PEiD"
		description = "Pack Master 1.0 (PEX Clone) -> WebtoolMaster"
		group = "134"
		function = "0"
	strings:
		$a0 = { 60 E8 01 ?? ?? ?? E8 83 C4 04 E8 01 ?? ?? ?? E9 5D 81 ED D3 22 40 ?? E8 04 02 ?? ?? E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 }
	condition:
		$a0 at pe.entry_point
}

rule pcg303d
{
	meta:
		author = "PEiD"
		description = "PC-Guard 3.00 - 4.02 -> Blagoje Ceklic"
		group = "135"
		function = "0"
	strings:
		$a0 = { 55 50 E8 ?? ?? ?? ?? 5D EB 01 E3 60 E8 03 ?? ?? ?? D2 EB 0B 58 EB 01 48 40 EB 01 }
	condition:
		$a0 at pe.entry_point
}

rule pcg4
{
	meta:
		author = "PEiD"
		description = "PC-Guard 4.03 - 4.15 -> Blagoje Ceklic"
		group = "135"
		function = "0"
	strings:
		$a0 = { FC 55 50 E8 ?? ?? ?? ?? 5D EB 01 E3 60 E8 03 ?? ?? ?? D2 EB 0B 58 EB 01 48 40 EB 01 }
	condition:
		$a0 at pe.entry_point
}

rule pcg5
{
	meta:
		author = "PEiD"
		description = "PC-Guard 5.0 -> Blagoje Ceklic"
		group = "135"
		function = "0"
	strings:
		$a0 = { FC 55 50 E8 ?? ?? ?? ?? 5D 60 E8 03 ?? ?? ?? ?? ?? ?? EB 01 ?? 58 EB 01 ?? 40 EB 01 ?? FF E0 0B 61 B8 }
	condition:
		$a0 at pe.entry_point
}

rule pcpeca
{
	meta:
		author = "PEiD"
		description = "PC PE Encryptor alpha preview -> The +Q, Plushmm & Mr. Nop"
		group = "136"
		function = "0"
	strings:
		$a0 = { 53 51 52 56 57 55 E8 ?? ?? ?? ?? 5D 8B CD 81 ED 33 30 40 ?? 2B 8D EE 32 40 ?? 83 E9 0B 89 8D F2 32 40 ?? 80 BD D1 32 40 ?? 01 0F 84 }
	condition:
		$a0 at pe.entry_point
}

rule pcs020
{
	meta:
		author = "PEiD"
		description = "PC Shrinker 0.20 -> Virogen"
		group = "137"
		function = "0"
	strings:
		$a0 = { E8 E8 01 ?? ?? 60 01 AD B3 27 40 ?? 68 }
	condition:
		$a0 at pe.entry_point
}

rule pcs029
{
	meta:
		author = "PEiD"
		description = "PC Shrinker 0.29 -> Virogen"
		group = "137"
		function = "0"
	strings:
		$a0 = { ?? BD ?? ?? ?? ?? 01 AD 55 39 40 ?? 8D B5 35 39 40 }
	condition:
		$a0 at pe.entry_point
}

rule pcs045
{
	meta:
		author = "PEiD"
		description = "PC Shrinker 0.45 -> Virogen"
		group = "137"
		function = "0"
	strings:
		$a0 = { ?? BD ?? ?? ?? ?? 01 AD E3 38 40 ?? FF B5 DF 38 40 }
	condition:
		$a0 at pe.entry_point
}

rule pcs071
{
	meta:
		author = "PEiD"
		description = "PC Shrinker 0.71 -> Virogen"
		group = "137"
		function = "0"
	strings:
		$a0 = { 9C 60 BD ?? ?? ?? ?? 01 AD 54 3A 40 ?? FF B5 50 3A 40 ?? 6A 40 FF 95 88 3A 40 ?? 50 50 2D ?? ?? ?? ?? 89 85 }
	condition:
		$a0 at pe.entry_point
}

rule pcs_x
{
	meta:
		author = "PEiD"
		description = "PC Shrinker 0.29 - 0.71 -> Virogen"
		group = "137"
		function = "0"
	strings:
		$a0 = { 9C 60 BD ?? ?? ?? ?? 01 AD ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 6A 40 FF 95 ?? ?? ?? ?? 50 50 2D ?? ?? ?? ?? 89 85 }
	condition:
		$a0 at pe.entry_point
}

rule peb02_20_wtd
{
	meta:
		author = "PEiD"
		description = "PEBundle 0.2 - 2.0b4 -> Jeremy Collake"
		group = "138"
		function = "0"
	strings:
		$a0 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 6A 04 68 ?? 10 ?? ?? 68 ?? 02 ?? ?? 6A ?? FF 95 }
	condition:
		$a0 at pe.entry_point
}

rule peb20b5
{
	meta:
		author = "PEiD"
		description = "PEBundle 2.0b5 - 3.0x -> Jeremy Collake"
		group = "138"
		function = "0"
	strings:
		$a0 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 01 AD ?? ?? ?? ?? 01 AD }
	condition:
		$a0 at pe.entry_point
}

rule peb20x
{
	meta:
		author = "PEiD"
		description = "PEBundle 2.0x - 2.4x-> Jeremy Collake"
		group = "138"
		function = "0"
	strings:
		$a0 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 83 BD }
	condition:
		$a0 at pe.entry_point
}

rule pebundle_h
{
	meta:
		author = "PEiD"
		description = "PEBundle 0.2 - 3.x -> Jeremy Collake"
		group = "138"
		function = "0"
	strings:
		$a0 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD }
	condition:
		$a0 at pe.entry_point
}

rule pec092
{
	meta:
		author = "PEiD"
		description = "PECompact 0.92 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD A5 4F 40 ?? F3 AA 01 AD 04 51 40 ?? FF B5 }
	condition:
		$a0 at pe.entry_point
}

rule pec094
{
	meta:
		author = "PEiD"
		description = "PECompact 0.94 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 }
	condition:
		$a0 at pe.entry_point
}

rule pec097
{
	meta:
		author = "PEiD"
		description = "PECompact 0.971 - 0.976 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 }
	condition:
		$a0 at pe.entry_point
}

rule pec0977
{
	meta:
		author = "PEiD"
		description = "PECompact 0.977 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB A0 86 40 ?? 87 DD 8B 85 2A 87 }
	condition:
		$a0 at pe.entry_point
}

rule pec0978
{
	meta:
		author = "PEiD"
		description = "PECompact 0.978 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 24 88 40 ?? 87 DD 8B 85 A9 88 }
	condition:
		$a0 at pe.entry_point
}

rule pec09781
{
	meta:
		author = "PEiD"
		description = "PECompact 0.978.1 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 49 87 40 ?? 87 DD 8B 85 CE 87 }
	condition:
		$a0 at pe.entry_point
}

rule pec09784
{
	meta:
		author = "PEiD"
		description = "PECompact 0.978.2 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB D1 84 40 ?? 87 DD 8B 85 56 85 }
	condition:
		$a0 at pe.entry_point
}

rule pec098
{
	meta:
		author = "PEiD"
		description = "PECompact 0.98 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB D7 84 40 ?? 87 DD 8B 85 5C 85 }
	condition:
		$a0 at pe.entry_point
}

rule pec099
{
	meta:
		author = "PEiD"
		description = "PECompact 0.99 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 2F 85 40 ?? 87 DD 8B 85 B4 85 }
	condition:
		$a0 at pe.entry_point
}

rule pec100
{
	meta:
		author = "PEiD"
		description = "PECompact 1.00 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB C4 84 40 ?? 87 DD 8B 85 49 85 }
	condition:
		$a0 at pe.entry_point
}

rule pec110b1
{
	meta:
		author = "PEiD"
		description = "PECompact 1.10b1 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 28 63 40 ?? 87 DD 8B 85 AD 63 }
	condition:
		$a0 at pe.entry_point
}

rule pec110b2
{
	meta:
		author = "PEiD"
		description = "PECompact 1.10b2 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 94 60 }
	condition:
		$a0 at pe.entry_point
}

rule pec110b3
{
	meta:
		author = "PEiD"
		description = "PECompact 1.10b3 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 95 }
	condition:
		$a0 at pe.entry_point
}

rule pec110b4
{
	meta:
		author = "PEiD"
		description = "PECompact 1.10b4 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 44 }
	condition:
		$a0 at pe.entry_point
}

rule pec110b5
{
	meta:
		author = "PEiD"
		description = "PECompact 1.10b5 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 49 }
	condition:
		$a0 at pe.entry_point
}

rule pec110b6
{
	meta:
		author = "PEiD"
		description = "PECompact 1.10b6 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 ?? ?? 87 DD 8B 85 9A 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 01 85 92 60 40 ?? BB B7 }
	condition:
		$a0 at pe.entry_point
}

rule pec110b7
{
	meta:
		author = "PEiD"
		description = "PECompact 1.10b7 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 9A 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 01 85 92 60 40 ?? BB 14 }
	condition:
		$a0 at pe.entry_point
}

rule pec120_201
{
	meta:
		author = "PEiD"
		description = "PECompact 1.20 - 1.20.1 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 9A 70 40 }
	condition:
		$a0 at pe.entry_point
}

rule pec122
{
	meta:
		author = "PEiD"
		description = "PECompact 1.22 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 ?? 70 40 ?? 90 90 01 85 9E 70 40 ?? BB F3 08 }
	condition:
		$a0 at pe.entry_point
}

rule pec123b3_241
{
	meta:
		author = "PEiD"
		description = "PECompact 1.23b3 - 1.24.1 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 ?? 70 40 ?? 90 90 01 85 9E 70 40 ?? BB D2 08 }
	condition:
		$a0 at pe.entry_point
}

rule pec1242_243
{
	meta:
		author = "PEiD"
		description = "PECompact 1.24.2 - 1.24.3 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 ?? 70 40 ?? 90 90 01 85 9E 70 40 ?? BB D2 09 }
	condition:
		$a0 at pe.entry_point
}

rule pec125
{
	meta:
		author = "PEiD"
		description = "PECompact 1.25 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 ?? 70 40 ?? 90 90 01 85 9E 70 40 ?? BB F3 0D }
	condition:
		$a0 at pe.entry_point
}

rule pec126b1_b2
{
	meta:
		author = "PEiD"
		description = "PECompact 1.26b1 - 1.26b2 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 ?? 70 40 ?? 90 90 01 85 9E 70 40 ?? BB 05 0E }
	condition:
		$a0 at pe.entry_point
}

rule pec133
{
	meta:
		author = "PEiD"
		description = "PECompact 1.33 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A6 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 ?? 80 40 ?? 90 90 01 85 9E 80 40 ?? BB E8 0E }
	condition:
		$a0 at pe.entry_point
}

rule pec134_40b1
{
	meta:
		author = "PEiD"
		description = "PECompact 1.34 - 1.40b1 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A6 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 ?? 80 40 ?? 90 90 01 85 9E 80 40 ?? BB F8 10 }
	condition:
		$a0 at pe.entry_point
}

rule pec140b2_b4
{
	meta:
		author = "PEiD"
		description = "PECompact 1.40b2 - 1.40b4 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 86 11 }
	condition:
		$a0 at pe.entry_point
}

rule pec140b5_b6
{
	meta:
		author = "PEiD"
		description = "PECompact 1.40b5 - 1.40b6 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 8A 11 }
	condition:
		$a0 at pe.entry_point
}

rule pec140_45
{
	meta:
		author = "PEiD"
		description = "PECompact 1.40 - 1.45 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB C3 11 }
	condition:
		$a0 at pe.entry_point
}

rule pec146
{
	meta:
		author = "PEiD"
		description = "PECompact 1.46 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 60 12 }
	condition:
		$a0 at pe.entry_point
}

rule pec147_50
{
	meta:
		author = "PEiD"
		description = "PECompact 1.47 - 1.50 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 5B 12 }
	condition:
		$a0 at pe.entry_point
}

rule pec155
{
	meta:
		author = "PEiD"
		description = "PECompact 1.55 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A2 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 ?? 80 40 ?? 90 90 01 85 9E 80 40 ?? BB 2D 12 }
	condition:
		$a0 at pe.entry_point
}

rule pec156
{
	meta:
		author = "PEiD"
		description = "PECompact 1.56 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 90 40 ?? 87 DD 8B 85 A2 90 40 ?? 01 85 03 90 40 ?? 66 C7 85 ?? 90 40 ?? 90 90 01 85 9E 90 40 ?? BB 2D 12 }
	condition:
		$a0 at pe.entry_point
}

rule pec160_65
{
	meta:
		author = "PEiD"
		description = "PECompact 1.60 - 1.65 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 80 40 ?? 87 DD 8B 85 D2 80 40 ?? 01 85 33 80 40 ?? 66 C7 85 ?? 80 40 ?? 90 90 01 85 CE 80 40 ?? BB BB 12 }
	condition:
		$a0 at pe.entry_point
}

rule pec166
{
	meta:
		author = "PEiD"
		description = "PECompact 1.66 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 ?? 87 DD 8B 85 E6 90 40 ?? 01 85 33 90 40 ?? 66 C7 85 ?? 90 40 ?? 90 90 01 85 DA 90 40 ?? 01 85 DE 90 40 ?? 01 85 E2 90 40 ?? BB 5B 11 }
	condition:
		$a0 at pe.entry_point
}

rule pec167
{
	meta:
		author = "PEiD"
		description = "PECompact 1.67 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 ?? 87 DD 8B 85 E6 90 40 ?? 01 85 33 90 40 ?? 66 C7 85 ?? 90 40 ?? 90 90 01 85 DA 90 40 ?? 01 85 DE 90 40 ?? 01 85 E2 90 40 ?? BB 8B 11 }
	condition:
		$a0 at pe.entry_point
}

rule pec168_76
{
	meta:
		author = "PEiD"
		description = "PECompact 1.68 - 1.84 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 ?? 87 DD 8B 85 E6 90 40 ?? 01 85 33 90 40 ?? 66 C7 85 ?? 90 40 ?? 90 90 01 85 DA 90 40 ?? 01 85 DE 90 40 ?? 01 85 E2 90 40 ?? BB 7B 11 }
	condition:
		$a0 at pe.entry_point
}

rule pec14_h
{
	meta:
		author = "PEiD"
		description = "PECompact 1.4x or above -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 }
	condition:
		$a0 at pe.entry_point
}

/*
Gets Thin / Anti-Debug / Default loaders ..
*/
rule pec2_a
{
	meta:
		author = "PEiD"
		description = "PECompact 2.00 alpha 38 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? 80 B8 ?? ?? ?? ?? 01 74 7A C6 80 ?? ?? ?? ?? 01 9C 55 53 51 57 52 56 8D 98 ?? ?? ?? ?? 8B 53 14 8B E8 6A 40 68 00 10 00 00 FF 73 04 6A 00 }
	condition:
		$a0 at pe.entry_point
}

rule pec2_BoB
{
	meta:
		author = "PEiD"
		description = "PECompact 2.xx -> Jeremy Collake"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 }
	condition:
		$a0
}

rule pec2_h
{
	meta:
		author = "PEiD"
		description = "PECompact 2.0x Heuristic Mode -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { FF FF FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 }
	condition:
		$a0 at pe.entry_point
}

rule pecrypt100_101_console
{
	meta:
		author = "PEiD"
		description = "PE Crypt 1.00/1.01/Console -> random, killa & acpizer"
		group = "140"
		function = "0"
	strings:
		$a0 = { E8 ?? ?? ?? ?? 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB }
	condition:
		$a0 at pe.entry_point
}

rule pecrypt102
{
	meta:
		author = "PEiD"
		description = "PE Crypt 1.02 -> random, killa & acpizer"
		group = "141"
		function = "0"
	strings:
		$a0 = { E8 ?? ?? ?? ?? 5B 83 EB 05 EB 04 52 4E 44 }
	condition:
		$a0 at pe.entry_point
}

rule pen1
{
	meta:
		author = "PEiD"
		description = "PEncrypt 1.0 -> junkcode"
		group = "142"
		function = "0"
	strings:
		$a0 = { 60 9C BE ?? 10 40 ?? 8B FE B9 28 03 ?? ?? BB 78 56 34 12 AD 33 C3 AB E2 FA 9D 61 }
	condition:
		$a0 at pe.entry_point
}

rule pen3
{
	meta:
		author = "PEiD"
		description = "PEncrypt 3.0 -> junkcode"
		group = "142"
		function = "0"
	strings:
		$a0 = { E8 ?? ?? ?? ?? 5D 81 ED 05 10 40 ?? 8D B5 24 10 40 ?? 8B FE B9 0F ?? ?? ?? BB ?? ?? ?? ?? AD 33 C3 E2 FA }
	condition:
		$a0 at pe.entry_point
}

rule pen31
{
	meta:
		author = "PEiD"
		description = "PEncrypt 3.1 -> junkcode"
		group = "142"
		function = "0"
	strings:
		$a0 = { E9 ?? ?? ?? ?? F0 0F C6 }
	condition:
		$a0
}

rule ped01
{
	meta:
		author = "PEiD"
		description = "PEDiminisher 0.1 -> Teraphy"
		group = "143"
		function = "0"
	strings:
		$a0 = { 5D 8B D5 81 ED A2 30 40 ?? 2B 95 91 33 40 ?? 81 EA 0B ?? ?? ?? 89 95 9A 33 40 ?? 80 BD 99 }
	condition:
		$a0 at pe.entry_point
}

rule pehardlock
{
	meta:
		author = "PEiD"
		description = "PE Hardlock / HASP Envelope -> Aladdin"
		group = "144"
		function = "0"
	strings:
		$a0 = { 55 8B EC 53 56 57 60 8B C4 A3 ?? ?? ?? ?? B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 3D ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? A1 ?? ?? ?? ?? 50 FF 15 }
	condition:
		$a0
}

rule peintro1
{
	meta:
		author = "PEiD"
		description = "PE Intro 1.0 -> Predator NLS"
		group = "146"
		function = "0"
	strings:
		$a0 = { 8B 04 24 9C 60 E8 ?? ?? ?? ?? 5D 81 ED 0A 45 40 ?? 80 BD 67 44 40 ?? ?? 0F 85 48 }
	condition:
		$a0 at pe.entry_point
}

rule pelock_10h
{
	meta:
		author = "PEiD"
		description = "PELock 1.0x Heuristic Mode -> Bartosz Wojcik"
		group = "147"
		function = "0"
	strings:
		$a0 = { 4C 6F 61 64 4C 69 62 72 61 72 79 41 ?? ?? 56 69 72 74 75 61 6C 41 6C 6C 6F 63 ?? 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C }
	condition:
		$a0 at pe.entry_point
}

rule pelocknt201
{
	meta:
		author = "PEiD"
		description = "PE Lock NT 2.01 -> :MARQUiS:"
		group = "148"
		function = "0"
	strings:
		$a0 = { EB 03 CD 20 EB EB 01 EB 1E EB 01 EB EB 02 CD 20 9C EB 03 CD }
	condition:
		$a0 at pe.entry_point
}

rule pelocknt202c
{
	meta:
		author = "PEiD"
		description = "PE Lock NT 2.02c -> :MARQUiS:"
		group = "148"
		function = "0"
	strings:
		$a0 = { EB 02 C7 85 1E EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 02 CD }
	condition:
		$a0 at pe.entry_point
}

rule pelocknt204
{
	meta:
		author = "PEiD"
		description = "PE Lock NT 2.04 -> :MARQUiS:"
		group = "148"
		function = "0"
	strings:
		$a0 = { EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60 EB 03 CD 20 EB EB 01 EB }
	condition:
		$a0 at pe.entry_point
}

rule pemangle
{
	meta:
		author = "PEiD"
		description = "PEMangle -> Lord Julus"
		group = "149"
		function = "0"
	strings:
		$a0 = { 60 9C BE ?? ?? ?? ?? 8B FE B9 ?? ?? ?? ?? BB 44 52 4F 4C AD 33 C3 }
	condition:
		$a0 at pe.entry_point
}

rule penight13
{
	meta:
		author = "PEiD"
		description = "PENightMare 1.3 -> FreddyK"
		group = "150"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D B9 ?? ?? ?? ?? 80 31 15 41 81 F9 }
	condition:
		$a0 at pe.entry_point
}

rule penight2b
{
	meta:
		author = "PEiD"
		description = "PENightMare 2 Beta -> FreddyK"
		group = "150"
		function = "0"
	strings:
		$a0 = { 60 E9 ?? ?? ?? ?? EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A }
	condition:
		$a0 at pe.entry_point
}

rule penguin
{
	meta:
		author = "PEiD"
		description = "PEnguinCrypt 1.0 -> Pingvin"
		group = "151"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? 55 50 67 64 FF 36 ?? ?? 67 64 89 26 ?? ?? BD 4B 48 43 42 B8 04 ?? ?? ?? CC 3C 04 75 04 90 90 C3 90 67 64 8F 06 ?? ?? 58 5D BB ?? ?? 40 ?? 33 C9 33 C0 32 0C 03 40 81 F8 ?? 01 ?? ?? 75 F4 }
	condition:
		$a0 at pe.entry_point
}

rule peninja
{
	meta:
		author = "PEiD"
		description = "PENinja -> +DZA Kracker/TNT!"
		group = "152"
		function = "0"
	strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
	condition:
		$a0
}

rule peninja_h
{
	meta:
		author = "PEiD"
		description = "PENinja modified -> +DZA"
		group = "152"
		function = "0"
	strings:
		$a0 = { 5D 8B C5 81 ED B2 2C 40 ?? 2B 85 94 3E 40 ?? 2D 71 02 ?? ?? 89 85 98 3E 40 ?? 0F B6 B5 9C 3E 40 ?? 8B FD }
	condition:
		$a0 at pe.entry_point
}

rule pep
{
	meta:
		author = "PEiD"
		description = "PE Packer -> Vecna"
		group = "153"
		function = "0"
	strings:
		$a0 = { FC 8B 35 70 01 40 ?? 83 EE 40 6A 40 68 ?? 30 10 }
	condition:
		$a0 at pe.entry_point
}

rule pepack099
{
	meta:
		author = "PEiD"
		description = "PE Pack 0.99 -> ANAKiN"
		group = "154"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 83 ED 06 80 BD E0 04 ?? ?? 01 0F 84 F2 }
	condition:
		$a0 at pe.entry_point
}

rule pepack10
{
	meta:
		author = "PEiD"
		description = "PE Pack 1.0 -> ANAKiN"
		group = "154"
		function = "0"
	strings:
		$a0 = { 74 ?? E9 }
	condition:
		$a0
}

rule pepass02
{
	meta:
		author = "PEiD"
		description = "PE Password 0.2 SMT/SMF"
		group = "155"
		function = "0"
	strings:
		$a0 = { E8 04 ?? ?? ?? 8B EC 5D C3 33 C0 5D 8B FD 81 ED 33 26 40 ?? 81 EF ?? ?? ?? ?? 83 EF 05 89 AD 88 27 40 ?? 8D 9D 07 29 40 ?? 8D B5 62 28 40 ?? 46 80 }
	condition:
		$a0 at pe.entry_point
}

rule peprot09
{
	meta:
		author = "PEiD"
		description = "PE Protect 0.9 -> Christoph Gabler"
		group = "156"
		function = "0"
	strings:
		$a0 = { 52 51 55 57 64 67 A1 30 ?? 85 C0 78 0D E8 ?? ?? ?? ?? 58 83 C0 07 C6 ?? C3 }
	condition:
		$a0
}

rule perplex101dev
{
	meta:
		author = "PEiD"
		description = "Perplex PE-Protector 1.01dev -> tC/PERPLEX"
		group = "195"
		function = "0"
	strings:
		$a0 = { 60 E9 8D 05 00 00 }
	condition:
		$a0
}

rule perplex101dev_h
{
	meta:
		author = "PEiD"
		description = "Perplex PE-Protector 1.01dev -> [tC]/PERPLEX"
		group = "195"
		function = "0"
	strings:
		$a0 = { E8 51 00 00 00 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 E8 01 00 00 00 9A 59 8D 95 CD 25 40 00 E8 01 00 00 00 69 58 66 BF 4D 4A E8 2E 00 00 00 8D 52 F9 E8 01 00 00 00 E8 5B 68 CC FF E2 9A FF E4 69 FF A5 AF 2F 40 00 E9 E8 B9 FF FF FF EB 03 C7 84 E8 51 C3 EB 03 C7 84 9A 59 41 EB F0 E8 01 00 00 00 9A 59 EB 02 0F E8 E8 01 00 00 00 69 58 E8 00 00 00 00 5D 81 ED F9 25 40 00 }
	condition:
		$a0 at pe.entry_point
}

rule pesh1b
{
	meta:
		author = "PEiD"
		description = "PESHiELD 0.1b MTE -> ANAKiN"
		group = "157"
		function = "0"
	strings:
		$a0 = { E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? B9 1B 01 ?? ?? D1 }
	condition:
		$a0 at pe.entry_point
}

/*
wtf!?
[pesh025]

60 E8 2B

name     = PESHiELD 0.25 -> ANAKiN
hardcore = 0
group    = 157
*/
rule pesh02
{
	meta:
		author = "PEiD"
		description = "PESHiELD 0.2 / 0.2b / 0.2b2 -> ANAKiN"
		group = "157"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04 }
	condition:
		$a0 at pe.entry_point
}

rule pesh025_x
{
	meta:
		author = "PEiD"
		description = "PESHiELD 0.25 Heuristic Mode -> ANAKiN"
		group = "157"
		function = "0"
	strings:
		$a0 = { 5D 83 ED 06 EB 02 EA 04 8D ?? 56 ?? ?? ?? ?? ?? ?? ?? ?? 8A ?? ?? 32 ?? 80 }
	condition:
		$a0
}

rule pesh0251
{
	meta:
		author = "PEiD"
		description = "PESHiELD 0.251 -> ANAKiN"
		group = "157"
		function = "0"
	strings:
		$a0 = { 5D 83 ED 06 EB 02 EA 04 8D }
	condition:
		$a0
}

rule peshit
{
	meta:
		author = "PEiD"
		description = "UPXShit 0.05 -> snaker"
		group = "158"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 83 F9 ?? 7E 06 80 30 ?? 40 E2 F5 E9 ?? ?? ?? FF }
	condition:
		$a0
}

rule pespin03
{
	meta:
		author = "PEiD"
		description = "PESpin 0.3 -> cyberbob"
		group = "158"
		function = "0"
	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 }
	condition:
		$a0
}

rule pespin041
{
	meta:
		author = "PEiD"
		description = "PESpin 0.41 -> cyberbob"
		group = "158"
		function = "0"
	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 02 D2 46 }
	condition:
		$a0
}

rule pespin070
{
	meta:
		author = "PEiD"
		description = "PESpin 0.70 -> cyberbob"
		group = "999"
		function = "0"
	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 88 39 40 00 8B 42 3C 03 C2 89 85 92 39 40 00 EB 01 DB 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D A6 39 40 00 53 8F 85 4A 38 40 00 BB ?? 00 00 00 B9 EC 0A 00 00 8D BD 36 3A 40 00 4F EB 01 AB 30 1C 39 FE CB E2 F9 EB 01 C8 68 CB 00 00 00 59 8D BD 56 44 40 00 E8 03 00 00 00 EB 04 FA EB FB 68 83 04 24 0C C3 8D C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 B3 5F 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D 99 39 40 00 8B D6 B9 10 00 00 00 AC 84 C0 74 06 C0 4E FF 03 E2 F5 E8 00 00 00 00 }
	condition:
		$a0
}

rule pespin10
{
	meta:
		author = "PEiD"
		description = "PESpin 1.0 -> cyberbob"
		group = "999"
		function = "0"
	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 C8 DC 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 D2 42 40 00 8B 42 3C 03 C2 89 85 DC 42 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D F0 42 40 00 53 8F 85 94 41 40 00 BB ?? 00 00 00 B9 8C 0B 00 00 8D BD 80 43 40 00 4F EB 01 AB 30 1C 39 FE CB E2 F9 EB 01 C8 68 CB 00 00 00 59 8D BD 40 4E 40 00 E8 03 00 00 00 EB 04 FA EB FB 68 83 04 24 0C C3 8D C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 FD 68 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 }
	condition:
		$a0
}

rule pespin11
{
	meta:
		author = "PEiD"
		description = "PESpin 1.1 -> cyberbob"
		group = "999"
		function = "0"
	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 C3 4B 40 00 8B 42 3C 03 C2 89 85 CD 4B 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D E1 4B 40 00 53 8F 85 D7 49 40 00 BB ?? 00 00 00 B9 FE 11 00 00 8D BD 71 4C 40 00 4F EB 07 FA EB 01 FF EB 04 E3 EB F8 69 30 1C 39 FE CB 49 9C C1 2C 24 06 F7 14 24 83 24 24 01 50 52 B8 83 B2 DC 12 05 44 4D 23 ED F7 64 24 08 8D 84 28 BD 2D 40 00 89 44 24 08 5A 58 8D 64 24 04 FF 64 24 FC FF EA EB 01 C8 E8 01 00 00 00 68 58 FE 48 1F 0F 84 94 02 00 00 75 01 9A 81 70 03 E8 98 68 EA 83 C0 21 80 40 FB EB A2 40 02 00 E0 91 32 68 CB 00 00 00 59 8D BD A3 5D 40 00 E8 03 00 00 00 EB 04 FA EB FB 68 83 04 24 0C C3 }
	condition:
		$a0
}

rule pespin13
{
	meta:
		author = "PEiD"
		description = "PESpin 1.3 -> cyberbob"
		group = "999"
		function = "0"
	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 AC DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 0D 4F 40 00 8B 42 3C 03 C2 89 85 17 4F 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D 2B 4F 40 00 53 8F 85 21 4D 40 00 EB 07 FA EB 01 FF EB 04 E3 EB F8 69 8B 59 38 03 DA 8B 3B 89 BD D0 4F 40 00 8D 5B 04 8B 1B 89 9D D5 4F 40 00 E8 00 00 00 00 58 01 68 05 68 F7 65 0F E2 B8 77 CE 2F B1 35 73 CE 2F B1 03 E0 F7 D8 81 2C 04 13 37 CF E1 FF 64 24 FC }
	condition:
		$a0
}

rule pespin13b2
{
	meta:
		author = "PEiD"
		description = "PESpin 1.3 beta2 -> cyberbob"
		group = "999"
		function = "0"
	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 71 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 ?? 4E 40 00 8B 42 3C 03 C2 89 85 ?? 4E 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D ?? 4E 40 00 53 8F 85 ?? 4C 40 00 EB 07 FA EB 01 FF EB 04 E3 EB F8 69 8B 59 38 03 DA 8B 3B 89 BD ?? 4F 40 00 8D 5B 04 8B 1B 89 9D ?? 4F 40 00 E8 00 00 00 00 58 01 68 05 68 BC 65 0F E2 B8 77 CE 2F B1 35 73 CE 2F B1 03 E0 F7 D8 81 2C 04 13 37 CF E1 FF 64 24 FC FF 25 10 BB ?? 00 00 00 B9 84 12 00 00 8D BD ?? 4F 40 00 4F EB 07 FA EB 01 FF EB 04 E3 EB F8 69 30 1C 39 FE CB 49 9C }
	condition:
		$a0
}

rule pespin_h
{
	meta:
		author = "PEiD"
		description = "PESpin 0.3x - 1.xx -> cyberbob"
		group = "158"
		function = "0"
	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 }
	condition:
		$a0
}

rule petite12
{
	meta:
		author = "PEiD"
		description = "PEtite 1.2 -> Ian Luck"
		group = "159"
		function = "0"
	strings:
		$a0 = { 9C 60 E8 CA ?? ?? ?? 03 ?? 04 ?? 05 ?? 06 ?? 07 ?? 08 }
	condition:
		$a0 at pe.entry_point
}

rule petite13
{
	meta:
		author = "PEiD"
		description = "PEtite 1.3 -> Ian Luck"
		group = "159"
		function = "0"
	strings:
		$a0 = { ?? ?? ?? ?? ?? 66 9C 60 50 8D 88 ?? F0 ?? ?? 8D 90 04 16 ?? ?? 8B DC 8B E1 68 ?? ?? ?? ?? 53 50 80 04 24 08 50 80 04 24 42 }
	condition:
		$a0 at pe.entry_point
}

rule petite14
{
	meta:
		author = "PEiD"
		description = "PEtite 1.4 -> Ian Luck"
		group = "159"
		function = "0"
	strings:
		$a0 = { 66 9C 60 50 8B D8 03 ?? 68 54 BC ?? ?? 6A ?? FF 50 14 8B CC }
	condition:
		$a0 at pe.entry_point
}

rule petite20
{
	meta:
		author = "PEiD"
		description = "PEtite 2.0 -> Ian Luck"
		group = "159"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? 66 9C 60 50 8B D8 03 ?? 68 54 BC ?? ?? 6A ?? FF 50 18 8B CC 8D A0 54 BC ?? ?? 8B C3 8D 90 E0 15 ?? ?? 68 }
	condition:
		$a0 at pe.entry_point
}

rule petite21x
{
	meta:
		author = "PEiD"
		description = "PEtite 2.x -> Ian Luck"
		group = "159"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? 66 9C 60 50 }
	condition:
		$a0
}

rule petite21
{
	meta:
		author = "PEiD"
		description = "PEtite 2.x [Level 0] -> Ian Luck"
		group = "159"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 66 9C 60 50 }
	condition:
		$a0 at pe.entry_point
}

rule petite22
{
	meta:
		author = "PEiD"
		description = "PEtite 2.x [Level 1/9] -> Ian Luck"
		group = "159"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 66 9C 60 50 }
	condition:
		$a0 at pe.entry_point
}

rule pex099
{
	meta:
		author = "PEiD"
		description = "PEX 0.99 -> bart/CrackPl"
		group = "160"
		function = "0"
	strings:
		$a0 = { 60 E8 01 ?? ?? ?? ?? 83 C4 04 E8 01 ?? ?? ?? ?? 5D 81 }
	condition:
		$a0 at pe.entry_point
}

rule pklite32_11
{
	meta:
		author = "PEiD"
		description = "PKLITE32 1.1 -> PKWARE Inc."
		group = "161"
		function = "0"
	strings:
		$a0 = { 55 8B EC A1 ?? ?? ?? ?? 85 C0 74 09 B8 01 ?? ?? ?? 5D C2 0C ?? 8B 45 0C 57 56 53 8B 5D 10 }
	condition:
		$a0 at pe.entry_point
}

rule progprot
{
	meta:
		author = "PEiD"
		description = "Program Protector XP 1.0 -> BluMental"
		group = "162"
		function = "0"
	strings:
		$a0 = { E8 ?? ?? ?? ?? 58 83 D8 05 89 C3 81 C3 ?? ?? ?? ?? 8B 43 64 50 }
	condition:
		$a0
}

rule protplus
{
	meta:
		author = "PEiD"
		description = "Protection Plus 4.x -> Concept Software"
		group = "163"
		function = "0"
	strings:
		$a0 = { 50 60 29 C0 64 FF 30 E8 ?? ?? ?? ?? 5D 83 ED 3C 89 E8 89 A5 14 ?? ?? ?? 2B 85 1C ?? ?? ?? 89 85 1C ?? ?? ?? 8D 85 27 03 ?? ?? 50 8B ?? 85 C0 0F 85 C0 ?? ?? ?? 8D BD 5B 03 ?? ?? 8D B5 43 03 ?? ?? E8 DD ?? ?? ?? 89 85 1F 03 ?? ?? 6A 40 68 ?? 10 ?? ?? 8B 85 28 ?? ?? ?? 50 6A }
	condition:
		$a0 at pe.entry_point
}

rule proact1
{
	meta:
		author = "PEiD"
		description = "ProActivate 1.0x -> TurboPower Software"
		group = "2006"
		function = "0"
	strings:
		$a0 = { 55 8B EC B9 0E 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 ?? ?? ?? ?? 90 90 90 90 90 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 A1 ?? ?? ?? ?? 83 C0 05 A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 0D 00 00 00 E8 85 E2 FF FF 81 3D ?? ?? ?? ?? 21 7E 7E 40 75 7A 81 3D ?? ?? ?? ?? 43 52 43 33 75 6E 81 3D ?? ?? ?? ?? 32 40 7E 7E 75 62 81 3D ?? ?? ?? ?? 21 7E 7E 40 75 56 81 3D ?? ?? ?? ?? 43 52 43 33 75 4A 81 3D ?? ?? ?? ?? 32 40 7E 7E 75 3E 81 3D ?? ?? ?? ?? 21 7E 7E 40 75 32 81 3D ?? ?? ?? ?? 43 52 43 33 }
	condition:
		$a0
}

rule prvtexe20a_22
{
	meta:
		author = "PEiD"
		description = "Private Exe 2.0a"
		group = "164"
		function = "0"
	strings:
		$a0 = { 53 E8 ?? ?? ?? ?? 5B 8B C3 2D }
	condition:
		$a0
}

rule ratpack
{
	meta:
		author = "PEiD"
		description = "RatPacker (glue) stub"
		group = "308"
		function = "0"
	strings:
		$a0 = { 40 20 FF ?? ?? ?? ?? ?? ?? ?? ?? BE ?? 60 40 ?? 8D BE ?? B0 FF FF }
	condition:
		$a0 at pe.entry_point
}

rule recrypt07b
{
	meta:
		author = "PEiD"
		description = "RE-Crypt 0.7b -> Crudd/RET"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 E8 00 00 00 00 5D 8B 7C 24 04 56 8B F5 81 C5 ?? ?? 00 00 89 6D 34 89 75 38 89 7D 64 8B FE 81 E7 00 FF FF FF 81 C7 ?? 00 00 00 }
	condition:
		$a0
}

rule sdprot110
{
	meta:
		author = "PEiD"
		description = "SDProtector Basic/Pro Edition 1.10 -> Randy Li"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 50 83 EC 08 64 A1 00 00 00 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 83 C4 08 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 64 8F 05 00 00 00 00 64 A3 00 00 00 00 83 C4 08 58 74 07 75 05 19 32 67 E8 E8 74 27 75 25 EB 00 EB FC 68 39 44 CD 00 59 9C 50 74 0F 75 0D E8 59 C2 04 00 55 8B EC E9 FA FF FF 0E E8 EF FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 59 03 00 00 03 C8 74 B8 75 B6 E8 00 00 }
	condition:
		$a0
}

rule sdprot112
{
	meta:
		author = "PEiD"
		description = "SDProtector Basic/Pro Edition 1.12 -> Randy Li"
		group = "999"
		function = "0"
	strings:
		$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 53 00 00 00 51 8B 4C 24 10 89 81 B8 00 00 00 B8 55 01 00 00 89 41 20 33 C0 89 41 04 89 41 08 89 41 0C 89 41 10 59 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 33 C0 64 FF 30 64 89 20 9C 80 4C 24 01 01 9D 90 90 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 64 8F 00 58 74 07 75 05 19 32 67 E8 E8 74 27 75 25 EB 00 EB FC 68 39 44 CD 00 59 9C 50 74 0F 75 0D E8 59 C2 04 00 55 8B EC E9 FA FF FF 0E E8 EF FF FF FF 56 57 53 78 03 79 01 E8 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 7B 03 00 00 03 C8 74 C4 75 C2 E8 }
	condition:
		$a0
}

rule sdprot116
{
	meta:
		author = "PEiD"
		description = "SDProtector Pro Edition 1.16 -> Randy Li"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 53 00 00 00 51 8B 4C 24 10 89 81 B8 00 00 00 B8 55 01 00 00 89 41 18 33 C0 89 41 04 89 41 08 89 41 0C 89 41 10 59 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 33 C0 64 FF 30 64 89 20 9C 80 4C 24 01 01 9D 90 90 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 64 8F 00 58 74 07 75 05 19 32 67 E8 E8 74 27 75 25 EB 00 EB FC 68 39 44 CD 00 59 9C 50 74 0F 75 0D E8 59 C2 04 00 55 8B EC E9 FA FF FF 0E E8 EF FF FF FF 56 57 53 78 03 79 01 E8 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 93 03 00 00 03 C8 74 C4 75 C2 E8 }
	condition:
		$a0
}

rule sentinel
{
	meta:
		author = "PEiD"
		description = "Sentinel Envelope -> Rainbow"
		group = "165"
		function = "0"
	strings:
		$a0 = { 64 A1 ?? ?? ?? ?? 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 0C 83 3D ?? ?? ?? ?? ?? 53 56 57 89 65 ?? 0F 85 ?? ?? ?? ?? FF 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 45 }
	condition:
		$a0
}

rule sentinel_640
{
	meta:
		author = "PEiD"
		description = "Sentinel SuperPro (Automatic Protection) 6.4.0 -> Safenet"
		group = "444"
		function = "0"
	strings:
		$a0 = { 68 ?? ?? ?? ?? 6A 01 6A 00 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 C9 3D B7 00 00 00 A1 ?? ?? ?? ?? 0F 94 C1 85 C0 89 0D ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 55 56 C7 05 ?? ?? ?? ?? 01 00 00 00 FF 15 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 25 FE FF DF 3F 0D 01 00 20 00 A3 ?? ?? ?? ?? 33 C0 50 C7 04 85 ?? ?? ?? ?? 00 00 00 00 E8 ?? ?? ?? ?? 83 C4 04 83 F8 64 7C ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF D6 68 ?? ?? ?? ?? FF D6 68 ?? ?? ?? ?? FF D6 68 ?? ?? ?? ?? FF D6 68 ?? ?? ?? ?? FF D6 A1 ?? ?? ?? ?? 8B 2D ?? ?? ?? ?? 66 8B 55 00 83 C5 08 }
	condition:
		$a0
}

rule softdefender
{
	meta:
		author = "PEiD"
		description = "Soft Defender 1.0 - 1.1 -> Randy Li"
		group = "166"
		function = "0"
	strings:
		$a0 = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 CD ?? 59 9C 50 74 0A 75 08 E8 59 C2 04 ?? 55 8B EC E8 F4 FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 ?? ?? ?? ?? 58 05 BA 01 ?? ?? 03 C8 74 BE 75 BC E8 }
	condition:
		$a0 at pe.entry_point
}

rule xlok
{
	meta:
		author = "PEiD"
		description = "XtreamLok -> XtreamLok.com"
		group = "167"
		function = "0"
	strings:
		$a0 = { 90 90 90 EB 29 }
	condition:
		$a0
}

rule softwrap
{
	meta:
		author = "PEiD"
		description = "Softwrap (encrypted) main stub / XLok"
		group = "167"
		function = "0"
	strings:
		$a0 = { 52 53 51 56 57 55 E8 ?? ?? ?? ?? 5D 81 ED 36 ?? ?? ?? E8 ?? 01 ?? ?? 60 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F }
	condition:
		$a0 at pe.entry_point
}

/*
I think this is only in unpacked files?!  But I only have Hitman 4 to test with ..  Blame snaker, it's not my sig ..
*/
rule secupack15
{
	meta:
		author = "PEiD"
		description = "SecuPack 1.5 -> SC Soft"
		group = "168"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 57 33 C0 89 45 F0 B8 CC 3A 40 ?? E8 E0 FC FF FF 33 C0 55 68 EA 3C 40 ?? 64 FF 30 64 89 20 6A ?? 68 80 ?? ?? ?? 6A 03 6A ?? 6A 01 ?? ?? ?? 80 }
	condition:
		$a0
}

rule securom7
{
	meta:
		author = "PEiD"
		description = "SecuROM 7.x.x.x -> Sony DADC"
		group = "666"
		function = "0"
	strings:
		$a0 = { 53 65 63 75 52 4F 4D 20 55 73 65 72 20 41 63 63 65 73 73 20 53 65 72 76 69 63 65 20 28 56 37 29 00 00 00 00 }
	condition:
		$a0 at pe.entry_point
}

rule smarte
{
	meta:
		author = "PEiD"
		description = "SmartE -> Microsoft"
		group = "666"
		function = "0"
	strings:
		$a0 = { EB 15 03 00 00 00 ?? 00 00 00 00 00 00 00 00 00 00 00 68 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 1D 00 00 00 8B C5 55 60 9C 2B 85 8F 07 00 00 89 85 83 07 00 00 FF 74 24 2C E8 BB 01 00 00 0F 82 2F 06 00 00 E8 8E 04 00 00 49 0F 88 23 06 }
	condition:
		$a0
}

rule specb2
{
	meta:
		author = "PEiD"
		description = "SPEC b2 -> Hayras"
		group = "169"
		function = "0"
	strings:
		$a0 = { 55 57 51 53 E8 ?? ?? ?? ?? 5D 8B C5 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 83 E8 09 89 85 ?? ?? ?? ?? 0F B6 }
	condition:
		$a0 at pe.entry_point
}

rule specb3
{
	meta:
		author = "PEiD"
		description = "SPEC b3 -> Hayras"
		group = "169"
		function = "0"
	strings:
		$a0 = { 5B 53 50 45 43 5D E8 ?? ?? ?? ?? 5D 8B C5 81 ED 41 24 40 ?? 2B 85 89 26 40 ?? 83 E8 0B 89 85 8D 26 40 ?? 0F B6 B5 91 26 40 ?? 8B FD }
	condition:
		$a0 at pe.entry_point
}

rule ssentry211
{
	meta:
		author = "PEiD"
		description = "SoftSentry 2.11 -> 20/20 Software"
		group = "170"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 EC ?? 53 56 57 E9 50 }
	condition:
		$a0
}

rule ssentry3
{
	meta:
		author = "PEiD"
		description = "SoftSentry 3.0 -> 20/20 Software"
		group = "171"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 EC ?? 53 56 57 E9 B0 06 }
	condition:
		$a0
}

rule shrinker32
{
	meta:
		author = "PEiD"
		description = "Shrinker 3.2 -> Blink Inc."
		group = "172"
		function = "0"
	strings:
		$a0 = { 83 3D ?? ?? ?? ?? ?? 55 8B EC 56 57 75 65 68 ?? 01 ?? ?? E8 ?? E6 FF FF 83 C4 04 8B 75 08 A3 ?? ?? ?? ?? 85 F6 74 1D 68 FF }
	condition:
		$a0 at pe.entry_point
}

rule shrinker33
{
	meta:
		author = "PEiD"
		description = "Shrinker 3.3 -> Blink Inc."
		group = "172"
		function = "0"
	strings:
		$a0 = { 83 3D ?? ?? ?? ?? ?? 55 8B EC 56 57 75 65 68 ?? 01 ?? ?? E8 }
	condition:
		$a0 at pe.entry_point
}

rule shrinker34
{
	meta:
		author = "PEiD"
		description = "Shrinker 3.4 -> Blink Inc."
		group = "172"
		function = "0"
	strings:
		$a0 = { 83 3D ?? ?? ?? ?? ?? 55 8B EC 56 57 75 6B 68 00 01 00 00 E8 ?? ?? ?? ?? 83 C4 04 8B 75 08 A3 ?? ?? ?? ?? 85 F6 74 23 83 7D 0C 03 77 1D 68 FF }
	condition:
		$a0 at pe.entry_point
}

rule shrinkwrap14
{
	meta:
		author = "PEiD"
		description = "ShrinkWrap 1.4 -> snyper"
		group = "173"
		function = "0"
	strings:
		$a0 = { 58 60 8B E8 55 33 F6 68 48 01 ?? ?? E8 49 01 ?? ?? EB }
	condition:
		$a0 at pe.entry_point
}

rule smoke12
{
	meta:
		author = "PEiD"
		description = "SmokesCrypt 1.2 -> Smoke"
		group = "174"
		function = "0"
	strings:
		$a0 = { 60 B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 8A 14 08 80 F2 ?? 88 14 08 41 83 F9 ?? 75 F1 }
	condition:
		$a0 at pe.entry_point
}

rule splasher1_3
{
	meta:
		author = "PEiD"
		description = "Splasher 1.0 - 3.0 -> Tola/Amok"
		group = "175"
		function = "0"
	strings:
		$a0 = { 9C 60 8B 44 24 24 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 50 E8 ED 02 ?? ?? 8C C0 0F 84 }
	condition:
		$a0 at pe.entry_point
}

rule stealthpe101
{
	meta:
		author = "PEiD"
		description = "Ste@lth PE 1.01 -> BGCorp"
		group = "176"
		function = "0"
	strings:
		$a0 = { BA ?? ?? ?? ?? FF E2 BA ?? ?? ?? ?? B8 ?? ?? ?? ?? 89 02 83 C2 03 B8 ?? ?? ?? ?? 89 02 83 C2 FD FF E2 }
	condition:
		$a0 at pe.entry_point
}

rule stealthpe21
{
	meta:
		author = "PEiD"
		description = "Ste@lth PE 2.10 -> BGCorp"
		group = "176"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? BA ?? ?? ?? ?? B9 00 10 40 00 31 01 83 C1 04 4A 75 F8 EB C0 }
	condition:
		$a0
}

rule stnpe10
{
	meta:
		author = "PEiD"
		description = "Stone's PE Encryptor 1.0"
		group = "177"
		function = "0"
	strings:
		$a0 = { 55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 ED 63 3A 40 ?? 2B 95 C2 3A 40 ?? 83 EA 0B 89 95 CB 3A 40 ?? 8D B5 CA 3A 40 ?? 0F B6 36 }
	condition:
		$a0 at pe.entry_point
}

rule stnpe113
{
	meta:
		author = "PEiD"
		description = "Stone's PE Encryptor 1.13"
		group = "177"
		function = "0"
	strings:
		$a0 = { 55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 ED 97 3B 40 ?? 2B 95 2D 3C 40 ?? 83 EA 0B 89 95 36 3C 40 ?? 01 95 24 3C 40 ?? 01 95 28 }
	condition:
		$a0 at pe.entry_point
}

rule stnpe20
{
	meta:
		author = "PEiD"
		description = "Stone's PE Encryptor 2.0"
		group = "177"
		function = "0"
	strings:
		$a0 = { 53 51 52 56 57 55 E8 ?? ?? ?? ?? 5D 81 ED 42 30 40 ?? FF 95 32 35 40 ?? B8 37 30 40 ?? 03 C5 2B 85 1B 34 40 ?? 89 85 27 34 40 ?? 83 }
	condition:
		$a0 at pe.entry_point
}

rule svkp1051
{
	meta:
		author = "PEiD"
		description = "SVK-Protector 1.051"
		group = "444"
		function = "0"
	strings:
		$a0 = { 60 EB 03 C7 84 E8 EB 03 C7 84 9A E8 00 00 00 00 5D 81 ED 10 00 00 00 EB 03 C7 84 E9 64 A0 23 00 00 00 EB }
	condition:
		$a0
}

rule svkp11
{
	meta:
		author = "PEiD"
		description = "SVKP 1.11 -> Pavol Cerven"
		group = "178"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 06 ?? ?? ?? 64 A0 23 }
	condition:
		$a0
}

rule svkp13x
{
	meta:
		author = "PEiD"
		description = "SVKP 1.3x -> Pavol Cerven"
		group = "178"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 06 ?? ?? ?? EB 05 B8 ?? ?? ?? ?? 64 A0 23 ?? ?? ?? EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 ?? ?? ?? 8D B5 C5 02 ?? ?? 56 80 06 44 46 E2 FA 8B 8D C1 02 ?? ?? 5E 55 51 6A }
	condition:
		$a0 at pe.entry_point
}

rule symviscafe3
{
	meta:
		author = "PEiD"
		description = "Symantec Visual Cafe 3.0"
		group = "28"
		function = "0"
	strings:
		$a0 = { 64 8B 05 ?? ?? ?? ?? 55 8B EC 6A FF 68 ?? ?? 40 ?? 68 ?? ?? 40 ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 08 50 53 56 57 89 65 E8 C7 45 FC }
	condition:
		$a0 at pe.entry_point
}

rule telock_03
{
	meta:
		author = "PEiD"
		description = "tElock 0.3 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { 66 8B C0 8D 24 24 60 9C E8 ?? ?? ?? ?? 5D D1 4D 12 81 6D 2A 79 AD 6C 4D EB 02 ?? ?? 8D B5 EC 01 }
	condition:
		$a0 at pe.entry_point
}

rule telock_041x
{
	meta:
		author = "PEiD"
		description = "tElock 0.41x -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { 66 8B C0 8D 24 24 EB 01 EB 60 EB 01 EB 9C E8 ?? ?? ?? ?? 5E 83 C6 50 8B FE 68 78 01 ?? ?? 59 EB 01 EB AC 54 E8 03 ?? ?? ?? 5C EB 08 }
	condition:
		$a0 at pe.entry_point
}

rule telock_042
{
	meta:
		author = "PEiD"
		description = "tElock 0.42 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { C1 EE ?? 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 ?? ?? ?? ?? 5E 83 C6 52 8B FE 68 79 01 ?? ?? 59 EB 01 EB AC 54 E8 03 ?? ?? ?? 5C EB 08 }
	condition:
		$a0 at pe.entry_point
}

rule telock_051
{
	meta:
		author = "PEiD"
		description = "tElock 0.51 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { C1 EE ?? 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 ?? ?? ?? ?? 5E 83 C6 5E 8B FE 68 79 01 ?? ?? 59 EB 01 EB AC 54 E8 03 ?? ?? ?? 5C EB 08 }
	condition:
		$a0 at pe.entry_point
}

rule telock_04x_05x
{
	meta:
		author = "PEiD"
		description = "tElock 0.4x - 0.5x -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { C1 EE ?? 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 ?? 8B FE 68 ?? 01 00 00 59 EB 01 }
	condition:
		$a0 at pe.entry_point
}

rule telock_060
{
	meta:
		author = "PEiD"
		description = "tElock 0.60 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { E9 ?? ?? ?? ?? 60 E8 ?? ?? ?? ?? 58 83 C0 08 F3 EB FF E0 83 C0 28 50 E8 ?? ?? ?? ?? 5E B3 33 8D 46 0E 8D 76 31 28 18 F8 73 ?? C3 8B FE B9 BE 01 }
	condition:
		$a0 at pe.entry_point
}

rule telock_061
{
	meta:
		author = "PEiD"
		description = "tElock 0.61 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { E9 ?? ?? ?? ?? 60 E8 ?? ?? ?? ?? 58 83 C0 08 F3 EB FF E0 83 C0 28 50 E8 ?? ?? ?? ?? 5E B3 33 8D 46 0E 8D 76 31 28 18 F8 73 ?? C3 8B FE B9 3C 02 }
	condition:
		$a0 at pe.entry_point
}

rule telock_06x
{
	meta:
		author = "PEiD"
		description = "tElock 0.6x -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { E9 ?? ?? ?? ?? 60 E8 ?? ?? ?? ?? 58 83 C0 08 F3 EB FF }
	condition:
		$a0 at pe.entry_point
}

rule telock_070
{
	meta:
		author = "PEiD"
		description = "tElock 0.70 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { 60 E8 BD 10 ?? ?? C3 83 }
	condition:
		$a0
}

rule telock_071
{
	meta:
		author = "PEiD"
		description = "tElock 0.71 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { 60 E8 ED 10 ?? ?? C3 83 }
	condition:
		$a0
}

rule telock_071b1
{
	meta:
		author = "PEiD"
		description = "tElock 0.71b1 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { 60 E8 72 11 ?? ?? C3 83 }
	condition:
		$a0
}

rule telock_071b2
{
	meta:
		author = "PEiD"
		description = "tElock 0.71b2 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { 60 E8 44 11 ?? ?? C3 83 }
	condition:
		$a0
}

rule telock_071b7
{
	meta:
		author = "PEiD"
		description = "tElock 0.71b7 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { 60 E8 48 11 ?? ?? C3 83 }
	condition:
		$a0
}

rule telock_071b8
{
	meta:
		author = "PEiD"
		description = "tElock 0.71b8 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { 60 E8 F3 10 00 00 C3 83 }
	condition:
		$a0
}

rule telock_080
{
	meta:
		author = "PEiD"
		description = "tElock 0.80 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { 60 E8 F9 11 ?? ?? C3 83 }
	condition:
		$a0
}

rule telock_085f
{
	meta:
		author = "PEiD"
		description = "tElock 0.85f -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { 60 E8 02 ?? ?? ?? CD 20 E8 ?? ?? ?? ?? 5E 2B C9 58 74 02 CD 20 B9 }
	condition:
		$a0
}

rule telock_hsm7x
{
	meta:
		author = "PEiD"
		description = "tElock 0.7x - 0.84 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? C3 83 }
	condition:
		$a0
}

rule telock_090
{
	meta:
		author = "PEiD"
		description = "tElock 0.90 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { ?? ?? E8 02 ?? ?? ?? E8 ?? E8 ?? ?? ?? ?? 5E 2B C9 58 74 02 CD 20 B9 FF 10 }
	condition:
		$a0 at pe.entry_point
}

rule telock_092a
{
	meta:
		author = "PEiD"
		description = "tElock 0.92a -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { E9 7E E9 FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? C8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 18 }
	condition:
		$a0 at pe.entry_point
}

rule telock_092b1
{
	meta:
		author = "PEiD"
		description = "tElock 0.92b1 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { E9 87 E9 FF FF ?? ?? ?? B8 }
	condition:
		$a0 at pe.entry_point
}

rule telock_092a1
{
	meta:
		author = "PEiD"
		description = "tElock 0.92a1 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { E9 6E E7 FF FF }
	condition:
		$a0
}

rule telock_0951
{
	meta:
		author = "PEiD"
		description = "tElock 0.95 build 1 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { E9 D5 E4 FF FF }
	condition:
		$a0
}

rule telock_0952
{
	meta:
		author = "PEiD"
		description = "tElock 0.95 build 2 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { E9 DD E4 FF FF }
	condition:
		$a0
}

rule telock_096
{
	meta:
		author = "PEiD"
		description = "tElock 0.96 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { E9 59 E4 FF FF }
	condition:
		$a0
}

rule telock_0981
{
	meta:
		author = "PEiD"
		description = "tElock 0.98b1 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { E9 25 E4 FF FF }
	condition:
		$a0
}

rule telock_0982
{
	meta:
		author = "PEiD"
		description = "tElock 0.98b2 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { E9 1B E4 FF FF }
	condition:
		$a0
}

rule telock_099
{
	meta:
		author = "PEiD"
		description = "tElock 0.99 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { E9 0D E4 FF FF }
	condition:
		$a0
}

rule telock_100
{
	meta:
		author = "PEiD"
		description = "tElock 1.00 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { E9 E5 E2 FF FF }
	condition:
		$a0
}

rule telock_09x
{
	meta:
		author = "PEiD"
		description = "tElock 0.9 - 1.0 (private) -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { E8 02 ?? ?? ?? E8 ?? E8 00 00 00 00 5E 2B C9 58 74 02 CD 20 B9 ?? ?? ?? ?? 8B C1 F8 73 02 CD 20 83 C6 33 8D ?? ?? ?? E8 02 ?? ?? ?? E8 ?? ?? ?? ?? 5A EB 01 E9 ?? ?? ?? ?? E9 }
	condition:
		$a0 at pe.entry_point
}

rule tgl
{
	meta:
		author = "PEiD"
		description = "The Guard Library"
		group = "180"
		function = "0"
	strings:
		$a0 = { 50 E8 ?? ?? ?? ?? 58 25 ?? F0 FF FF 8B C8 83 C1 60 51 83 C0 40 83 EA 06 52 FF 20 9D C3 }
	condition:
		$a0 at pe.entry_point
}

rule thinstall
{
	meta:
		author = "PEiD"
		description = "Thinstall 2.x -> Jitit Inc"
		group = "181"
		function = "0"
	strings:
		$a0 = { B8 EF BE AD DE 50 6A 00 FF 15 ?? ?? ?? 00 E9 ?? FF FF FF }
	condition:
		$a0
}

rule thinstall25x
{
	meta:
		author = "PEiD"
		description = "Thinstall 2.5xx -> Jitit Inc"
		group = "2005"
		function = "0"
	strings:
		$a0 = { 55 8B EC B8 ?? ?? ?? ?? BB ?? ?? ?? ?? 50 E8 00 00 00 00 58 2D ?? 1A 00 00 B9 ?? 1A 00 00 BA ?? 1B 00 00 BE 00 10 00 00 BF ?? 53 00 00 BD ?? 1A 00 00 03 E8 81 75 00 ?? ?? ?? ?? ?? 75 04 ?? ?? ?? ?? 81 75 08 ?? ?? ?? ?? 81 75 0C ?? ?? ?? ?? 81 75 10 ?? ?? ?? ?? 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3B F1 7C 04 3B F2 7C 02 89 2E 83 C6 04 3B F7 7C E3 58 50 68 00 00 40 00 68 80 5A }
	condition:
		$a0
}

rule thinstall2628
{
	meta:
		author = "PEiD"
		description = "Thinstall 2.628 -> Jitit Inc"
		group = "2005"
		function = "0"
	strings:
		$a0 = { E8 00 00 00 00 58 BB 34 1D 00 00 2B C3 50 68 00 00 40 00 68 00 40 00 00 68 BC 00 00 00 E8 C3 FE FF FF E9 99 FF FF FF CC CC CC CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 }
	condition:
		$a0
}

rule thinstall3035
{
	meta:
		author = "PEiD"
		description = "Thinstall 3.035 -> Jitit Inc"
		group = "2005"
		function = "0"
	strings:
		$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 28 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 A4 5E E9 F0 FE FF FF 33 C0 EB 05 8B C7 2B 45 0C 5E 5F 5B C9 C2 08 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 C3 B9 08 00 00 00 E8 01 00 00 00 C3 33 C0 E8 E1 FF FF FF 13 C0 E2 F7 C3 33 C9 41 E8 D4 FF FF FF 13 C9 E8 CD FF FF FF 72 F2 C3 }
	condition:
		$a0
}

rule themida1201
{
	meta:
		author = "PEiD"
		description = "themida 1.2.0.1 -> Oreans Technologies"
		group = "999"
		function = "0"
	strings:
		$a0 = { B8 00 00 ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 ?? ?? ?? 00 03 C7 B9 ?? ?? ?? 00 03 CF EB 0A B8 ?? ?? ?? ?? B9 5A ?? ?? ?? 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D 26 00 00 00 B9 EF 01 00 00 C6 00 E9 83 E9 05 89 48 01 61 E9 AF 01 00 00 02 00 00 00 91 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$a0
}

rule ugpack
{
	meta:
		author = "PEiD"
		description = "UG2002 Cruncher 0.3Beta -> DAEMON"
		group = "182"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? E8 0D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 58 }
	condition:
		$a0 at pe.entry_point
}

rule upack1x
{
	meta:
		author = "PEiD"
		description = "Upack 0.11 / 0.12 beta -> Dwing"
		group = "444"
		function = "0"
	strings:
		$a0 = { BE 48 ?? ?? ?? AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 }
	condition:
		$a0
}

rule upack2
{
	meta:
		author = "PEiD"
		description = "Upack 0.20 beta -> Dwing"
		group = "444"
		function = "0"
	strings:
		$a0 = { BE 88 ?? ?? ?? AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 }
	condition:
		$a0
}

rule upack21
{
	meta:
		author = "PEiD"
		description = "Upack 0.21 beta -> Dwing"
		group = "999"
		function = "0"
	strings:
		$a0 = { BE 88 ?? ?? ?? AD 8B F8 6A 04 95 A5 33 C0 AB 48 AB F7 D8 59 F3 AB C1 E0 0A B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 }
	condition:
		$a0
}

rule upack22_23
{
	meta:
		author = "PEiD"
		description = "Upack 0.22 / 0.23 beta -> Dwing"
		group = "999"
		function = "0"
	strings:
		$a0 = { 6A 07 BE 88 ?? ?? ?? AD 8B F8 59 95 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 59 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 }
	condition:
		$a0
}

rule upack24_28
{
	meta:
		author = "PEiD"
		description = "Upack 0.24 - 0.29 beta -> Dwing"
		group = "999"
		function = "0"
	strings:
		$a0 = { BE 88 ?? ?? ?? AD 8B F8 95 AD 91 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 B0 }
	condition:
		$a0
}

rule upack29_30
{
	meta:
		author = "PEiD"
		description = "Upack 0.29 / 0.30 beta -> Dwing"
		group = "444"
		function = "0"
	strings:
		$a0 = { BE ?? ?? ?? ?? AD 8B F8 95 AD 91 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 }
	condition:
		$a0 at pe.entry_point
}

rule upack_033_alpha
{
	meta:
		author = "PEiD"
		description = "Upack 0.33 alpha -> Dwing"
		group = "444"
		function = "0"
	strings:
		$a0 = { BE E8 11 40 00 AD 50 AD 50 66 BE 58 01 6A 12 BF ?? ?? ?? ?? 59 F3 A5 83 C8 FF 8B DF AB 40 AB 40 B1 04 F3 AB C1 E0 0A B5 10 F3 AB BF ?? ?? ?? ?? E9 ?? ?? ?? ?? 47 65 74 50 }
	condition:
		$a0
}

rule upack_034_alpha
{
	meta:
		author = "PEiD"
		description = "Upack 0.34 alpha -> Dwing"
		group = "444"
		function = "0"
	strings:
		$a0 = { BE E8 11 40 00 AD 50 AD 50 66 BE 58 01 6A 12 BF ?? ?? ?? ?? 59 F3 A5 83 C8 FF 8B DF AB 40 AB 40 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB BF ?? ?? ?? ?? E9 ?? ?? ?? ?? 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 10 00 00 D7 11 00 00 00 00 00 00 00 00 00 00 00 00 2A 10 00 00 E8 11 00 }
	condition:
		$a0
}

rule upack_036_beta
{
	meta:
		author = "PEiD"
		description = "Upack 0.36 beta -> Dwing"
		group = "444"
		function = "0"
	strings:
		$a0 = { BE E0 11 40 00 FF 36 E9 C3 00 00 00 48 01 ?? ?? ?? ?? ?? 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 18 10 00 00 10 00 00 00 00 ?? ?? 00 00 00 40 00 00 10 00 00 00 02 00 00 04 00 00 00 00 00 36 00 04 }
	condition:
		$a0
}

rule upack39
{
	meta:
		author = "PEiD"
		description = "Upack 0.39 beta -> Dwing"
		group = "444"
		function = "0"
	strings:
		$a0 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 39 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 ?? 00 00 ?? 00 00 ?? 00 00 ?? ?? 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? ?? 14 00 00 00 00 ?? ?? ?? ?? ?? ?? 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? ?? ?? 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB 8B 7E 0C 57 51 E9 ?? ?? ?? ?? 56 10 E2 E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 99 59 D1 E8 13 D2 E2 FA 5D 03 EA 45 59 89 6B 08 56 8B F7 2B F5 F3 A4 AC 5E B1 80 AA 3B 7E 34 0F 82 AC FE FF FF 58 5F 59 E3 1B 8A 07 47 04 18 3C 02 73 F7 8B 07 3C ?? 75 F3 B0 00 0F C8 03 46 38 2B C7 AB E2 E5 5E 5D 59 46 AD 85 C0 74 1F 51 56 97 FF D1 93 AC 84 C0 75 FB 38 06 74 EA 8B C6 79 05 46 33 C0 66 AD 50 }
	condition:
		$a0
}

rule WinUpackv0_39final
{
	meta:
		author = "PEiD"
		description = "UPack 0.39 final -> Dwing"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 39 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 ?? 00 00 ?? 00 00 ?? 00 00 ?? ?? 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? ?? 14 00 00 00 00 ?? ?? ?? ?? ?? ?? 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 ?? ?? ?? ?? ?? ?? ?? ?? DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? ?? ?? 00 00 00 }
	condition:
		$a0
}

rule upack_0399
{
	meta:
		author = "PEiD"
		description = "UPack 0.399 -> Dwing"
		group = "444"
		function = "0"
	strings:
		$a0 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 3A 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 ?? 00 00 ?? 00 00 10 00 00 ?? ?? 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? ?? 14 00 00 00 00 ?? ?? ?? ?? ?? 00 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 ?? ?? ?? ?? ?? ?? ?? ?? DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? ?? ?? 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 }
	condition:
		$a0
}

rule upack_028_0399
{
	meta:
		author = "PEiD"
		description = "Upack 0.28 - 0.399 (With relocs) - Delphi, .NET, DLL -> Dwing"
		group = "444"
		function = "0"
	strings:
		$a0 = { 60 E8 09 00 00 00 ?? ?? ?? 00 E9 06 02 00 00 33 C9 5E 87 0E E3 F4 2B F1 8B DE AD 2B D8 AD 03 C3 50 97 AD 91 F3 A5 5E AD 56 91 01 1E AD E2 FB AD 8D 6E 10 01 5D 00 8D 7D 1C B5 ?? F3 AB 5E AD 53 50 51 97 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 B0 01 E3 29 8B D7 2B 55 0C 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 14 93 FF 16 5A 9F 12 C0 D0 E9 74 0E 9E 1A F2 74 E4 B4 00 33 C9 B5 01 FF 56 08 33 C9 FF 66 1C B1 30 8B 5D 0C 03 D1 FF 16 73 4C 03 D1 FF 16 72 19 03 D1 FF 16 72 29 3C 07 B0 09 72 02 B0 0B 50 8B C7 2B 45 0C 8A 00 FF 66 18 83 C2 60 FF 16 87 5D 10 73 0C 03 D1 FF 16 87 5D }
	condition:
		$a0
}

rule star_force
{
	meta:
		author = "PEiD"
		description = "StarForce Protection Driver -> Protection Technology"
		group = "444"
		function = "0"
	strings:
		$a0 = { 57 68 ?? 0D 01 00 68 00 ?? ?? 00 E8 50 ?? FF FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 }
	condition:
		$a0
}

rule upxfreak_01_delphi
{
	meta:
		author = "PEiD"
		description = "UPXFreak 0.1 (Borland Delphi) -> HMX0101"
		group = "444"
		function = "0"
	strings:
		$a0 = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 00 ?? ?? ?? 00 03 00 00 00 ?? ?? ?? ?? 00 10 00 00 00 00 ?? ?? ?? ?? 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 34 50 45 00 ?? ?? ?? 00 FF FF 00 00 ?? 24 ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 40 00 00 C0 00 00 ?? ?? ?? ?? 00 00 ?? 00 00 00 ?? 1E ?? 00 ?? F7 ?? 00 A6 4E 43 00 ?? 56 ?? 00 AD D1 42 00 ?? F7 ?? 00 A1 D2 42 00 ?? 56 ?? 00 0B 4D 43 00 ?? F7 ?? 00 ?? F7 ?? 00 ?? 56 ?? 00 ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? 77 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 77 ?? ?? 00 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? 00 }
	condition:
		$a0
}

rule msvc3
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 3.0"
		group = "444"
		function = "0"
	strings:
		$a0 = { 64 A1 00 00 00 00 55 ?? ?? 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 ?? ?? ?? ?? ?? 00 00 83 EC 10 }
	condition:
		$a0
}

rule upackgen
{
	meta:
		author = "PEiD"
		description = "Upack 0.1x - 0.2x beta -> Dwing"
		group = "444"
		function = "0"
	strings:
		$a0 = { BE ?? ?? ?? ?? AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 1C F3 AB AD 50 97 51 }
	condition:
		$a0
}

rule upx080_84
{
	meta:
		author = "PEiD"
		description = "UPX 0.80 - 0.84 -> Markus & Laszlo"
		group = "183"
		function = "0"
	strings:
		$a0 = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 ?? ?? ?? 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 EF 75 09 8B 1E 83 EE FC }
	condition:
		$a0 at pe.entry_point
}

rule upx_1x
{
	meta:
		author = "PEiD"
		description = "UPX 0.89.6 - 1.02 / 1.05 - 2.90 -> Markus & Laszlo"
		group = "183"
		function = "0"
	strings:
		$a0 = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 ?? ?? ?? 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 ?? 8B 1E 83 EE FC }
	condition:
		$a0 at pe.entry_point
}

rule upx_sac_h
{
	meta:
		author = "PEiD"
		description = "UPX modified stub -> SAC/uNPACKinG gODS"
		group = "183"
		function = "0"
	strings:
		$a0 = { 79 07 0F B7 07 47 50 47 B9 57 48 F2 AE 55 FF 96 84 ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB D8 FF 96 88 ?? ?? ?? 61 E9 ?? ?? ?? FF }
	condition:
		$a0 at pe.entry_point
}

rule upx051
{
	meta:
		author = "PEiD"
		description = "UPX 0.51 -> Markus & Laszlo"
		group = "183"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 8D B0 D8 01 ?? ?? 83 CD FF 31 DB ?? ?? ?? ?? 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 0B 8A 06 46 88 07 47 EB EB 90 }
	condition:
		$a0 at pe.entry_point
}

rule upx051dll
{
	meta:
		author = "PEiD"
		description = "UPX 0.51 DLL -> Markus & Laszlo"
		group = "183"
		function = "0"
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 7D 01 00 00 60 E8 00 00 00 00 58 83 E8 48 50 8D B8 ?? ?? ?? ?? 57 8D B0 E0 01 00 00 83 CD FF 31 DB 90 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 0B 8A 06 46 88 07 47 EB EB }
	condition:
		$a0 at pe.entry_point
}

rule upx060_61
{
	meta:
		author = "PEiD"
		description = "UPX 0.60 - 0.61 -> Markus & Laszlo"
		group = "183"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 8D B0 E8 01 ?? ?? 83 CD FF 31 DB ?? ?? ?? ?? 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 0B 8A 06 46 88 07 47 EB EB 90 }
	condition:
		$a0 at pe.entry_point
}

rule upx060dll
{
	meta:
		author = "PEiD"
		description = "UPX 0.6x DLL -> Markus & Laszlo"
		group = "183"
		function = "0"
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 8D 01 00 00 60 E8 00 00 00 00 58 83 E8 48 50 8D B8 ?? ?? ?? ?? 57 8D B0 F0 01 00 00 83 CD FF 31 DB 90 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 0B 8A 06 46 88 07 47 EB EB }
	condition:
		$a0 at pe.entry_point
}

rule upx062
{
	meta:
		author = "PEiD"
		description = "UPX 0.62 -> Markus & Laszlo"
		group = "183"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 8D B0 F0 01 ?? ?? 83 CD FF 31 DB 90 90 90 EB 08 90 90 8A 06 46 88 07 47 01 DB 75 07 }
	condition:
		$a0 at pe.entry_point
}

rule upx070
{
	meta:
		author = "PEiD"
		description = "UPX 0.70 -> Markus & Laszlo"
		group = "183"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 8D B0 EC 01 ?? ?? 83 CD FF 31 DB EB 07 90 8A 06 46 88 07 47 01 DB 75 07 }
	condition:
		$a0 at pe.entry_point
}

rule upx070dll
{
	meta:
		author = "PEiD"
		description = "UPX 0.70 DLL -> Markus & Laszlo"
		group = "183"
		function = "0"
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 99 01 00 00 60 E8 00 00 00 00 58 83 E8 48 50 8D B8 ?? ?? ?? ?? 57 66 81 87 00 00 00 00 00 00 8D B0 FC 01 00 00 83 CD FF 31 DB EB 0C }
	condition:
		$a0 at pe.entry_point
}

rule upx071_72
{
	meta:
		author = "PEiD"
		description = "UPX 0.71 - 0.72 -> Markus & Laszlo"
		group = "183"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 83 CD FF 31 DB 5E 8D BE FA ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 81 C6 B3 01 ?? ?? EB 0A ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 }
	condition:
		$a0 at pe.entry_point
}

rule upx072dll
{
	meta:
		author = "PEiD"
		description = "UPX 0.71 - 0.72 DLL -> Markus & Laszlo"
		group = "183"
		function = "0"
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 95 01 00 00 60 E8 00 00 00 00 83 CD FF 31 DB 5E 8D BE ?? ?? ?? ?? 57 66 81 87 00 00 00 00 00 00 81 C6 B1 01 00 00 EB 07 90 8A 06 46 88 07 47 01 DB 75 07 }
	condition:
		$a0 at pe.entry_point
}

rule upxs
{
	meta:
		author = "PEiD"
		description = "UPX-Scrambler RC1.x -> ?OnT?oL"
		group = "183"
		function = "0"
	strings:
		$a0 = { 90 61 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }
	condition:
		$a0 at pe.entry_point
}

rule upxm
{
	meta:
		author = "PEiD"
		description = "UPX MODifier 0.1x -> snaker"
		group = "183"
		function = "0"
	strings:
		$a0 = { 50 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD }
	condition:
		$a0 at pe.entry_point
}

rule upxpr10x
{
	meta:
		author = "PEiD"
		description = "UPX Protector 1.0x -> BlindAngel/TMG"
		group = "183"
		function = "0"
	strings:
		$a0 = { EB EC ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 }
	condition:
		$a0 at pe.entry_point
}

rule upx_dll
{
	meta:
		author = "PEiD"
		description = "UPX 0.80 - 1.24 DLL -> Markus & Laszlo"
		group = "183"
		function = "0"
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }
	condition:
		$a0 at pe.entry_point
}

rule upx103_04
{
	meta:
		author = "PEiD"
		description = "UPX 1.03 - 1.04 -> Markus & Laszlo"
		group = "183"
		function = "0"
	strings:
		$a0 = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 8A 07 72 EB B8 01 ?? ?? ?? 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 ?? 8B 1E 83 EE FC }
	condition:
		$a0 at pe.entry_point
}

rule upx1x_delphi
{
	meta:
		author = "PEiD"
		description = "UPX 0.89.6 - 1.02 / 1.05 - 2.90 (Delphi) stub -> Markus & Laszlo"
		group = "183"
		function = "0"
	strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 83 CD FF EB 0E ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B }
	condition:
		$a0 at pe.entry_point
}

rule upx81_84_h
{
	meta:
		author = "PEiD"
		description = "UPX 0.81 - 0.84 modified -> Markus & Laszlo"
		group = "183"
		function = "0"
	strings:
		$a0 = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB ?? ED B8 01 ?? ?? ?? 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 EF }
	condition:
		$a0 at pe.entry_point
}

rule upx1x_h
{
	meta:
		author = "PEiD"
		description = "UPX 0.89.6 - 1.02 / 1.05 - 2.90 modified -> Markus & Laszlo"
		group = "183"
		function = "0"
	strings:
		$a0 = { 07 8B 1E 83 EE FC 11 DB ?? ED B8 01 ?? ?? ?? 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 }
	condition:
		$a0 at pe.entry_point
}

rule upx103_04_h
{
	meta:
		author = "PEiD"
		description = "UPX 1.03 - 1.04 modified -> Markus & Laszlo"
		group = "183"
		function = "0"
	strings:
		$a0 = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB 8A 07 ?? EB B8 01 ?? ?? ?? 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF }
	condition:
		$a0 at pe.entry_point
}

rule upx_alt_h
{
	meta:
		author = "PEiD"
		description = "UPX alternative stub -> Markus & Laszlo"
		group = "183"
		function = "0"
	strings:
		$a0 = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB ?? ED B8 01 ?? ?? ?? 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B }
	condition:
		$a0 at pe.entry_point
}

rule upx_eclipse
{
	meta:
		author = "PEiD"
		description = "UPX + ECLiPSE layer -> TEAM ECLiPSE"
		group = "184"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 33 D2 EB 01 0F 56 EB 01 0F E8 03 ?? ?? ?? EB 01 0F EB 01 0F 5E EB 01 }
	condition:
		$a0 at pe.entry_point
}

rule upxshit06
{
	meta:
		author = "PEiD"
		description = "UPXShit 0.06 -> snaker"
		group = "158"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 80 34 08 ?? E2 FA E9 ?? ?? ?? FF }
	condition:
		$a0
}

rule upx_hit001
{
	meta:
		author = "PEiD"
		description = "UPX$HiT 0.0.1 -> dj-siba"
		group = "158"
		function = "0"
	strings:
		$a0 = { 94 BC ?? ?? ?? ?? B9 ?? ?? ?? ?? 80 34 0C ?? E2 FA 94 }
	condition:
		$a0 at pe.entry_point
}

rule vbox42
{
	meta:
		author = "PEiD"
		description = "VBOX 4.2 MTE -> WeijunLi"
		group = "185"
		function = "0"
	strings:
		$a0 = { 8C E0 0B C5 8C E0 0B C4 03 C5 74 ?? 74 ?? 8B C5 }
	condition:
		$a0 at pe.entry_point
}

rule vbox43
{
	meta:
		author = "PEiD"
		description = "VBOX 4.3 - 4.6.x -> WeijunLi"
		group = "185"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 C4 E8 56 57 BE ?? ?? ?? ?? 8B 45 08 89 46 4C FF 75 0C 8F 46 50 8B 45 10 89 46 54 56 E8 ?? 00 00 00 5F 5E C9 C2 0C 00 }
	condition:
		$a0 at pe.entry_point
}

rule vprotect
{
	meta:
		author = "PEiD"
		description = "Visual Protect -> Visage"
		group = "186"
		function = "0"
	strings:
		$a0 = { 55 8B EC 51 53 56 57 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? A1 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 6A ?? FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 51 E8 }
	condition:
		$a0
}

rule vgcrypt075
{
	meta:
		author = "PEiD"
		description = "Virogen Crypt 0.75"
		group = "187"
		function = "0"
	strings:
		$a0 = { 9C 55 E8 EC ?? ?? ?? 87 D5 5D 60 87 D5 80 BD 15 27 40 ?? 01 }
	condition:
		$a0 at pe.entry_point
}

rule vob5
{
	meta:
		author = "PEiD"
		description = "VOB ProtectCD 5 -> Pinnacle"
		group = "188"
		function = "0"
	strings:
		$a0 = { 36 3E 26 8A C0 60 E8 }
	condition:
		$a0
}

rule vobx
{
	meta:
		author = "PEiD"
		description = "VOB ProtectCD Heuristic -> Pinnacle"
		group = "188"
		function = "0"
	strings:
		$a0 = { 5F 81 EF ?? ?? ?? ?? BE ?? ?? 40 ?? 8B 87 ?? ?? ?? ?? 03 C6 57 56 8C A7 ?? ?? ?? ?? FF 10 89 87 ?? ?? ?? ?? 5E 5F }
	condition:
		$a0 at pe.entry_point
}

rule winkript1
{
	meta:
		author = "PEiD"
		description = "Winkript 1.0 -> Mr. Crimson/WKT"
		group = "189"
		function = "0"
	strings:
		$a0 = { 33 C0 8B B8 ?? ?? ?? ?? 8B 90 04 ?? ?? ?? 85 FF 74 1B 33 C9 50 EB 0C 8A 04 39 C0 C8 04 34 1B 88 04 39 41 3B CA 72 F0 58 }
	condition:
		$a0 at pe.entry_point
}

rule wiseinstall
{
	meta:
		author = "PEiD"
		description = "Wise Installer stub"
		group = "306"
		function = "0"
	strings:
		$a0 = { 53 54 55 42 33 32 2E 45 58 45 ?? 5F 4D 61 69 6E 57 6E 64 50 72 6F 63 40 31 36 ?? 5F 53 }
	condition:
		$a0 at pe.entry_point
}

rule wiseinstall2
{
	meta:
		author = "PEiD"
		description = "Wise Installer stub"
		group = "999"
		function = "0"
	strings:
		$a0 = { 81 EC ?? 0F 00 00 ?? ?? 6A 04 FF 15 ?? 61 40 00 33 ?? 89 ?? 24 ?? 89 ?? 24 ?? 89 ?? 24 ?? 89 ?? 24 ?? 89 ?? 24 ?? FF 15 A4 60 40 00 8A 08 80 F9 22 89 44 24 ?? 75 2A EB 05 80 F9 22 74 10 40 8A 08 ?? ?? 89 44 24 ?? 75 F0 80 F9 22 75 17 40 89 44 24 ?? EB 10 80 F9 20 74 10 40 8A 08 89 44 24 ?? ?? ?? 75 F0 80 38 20 75 0A 40 80 38 20 74 FA 89 44 24 ?? 8A ?? 80 ?? 2F 74 ?? 8B ?? EB 08 80 ?? 3D 74 07 ?? 8A ?? ?? ?? 75 F4 }
	condition:
		$a0
}

rule wise10291
{
	meta:
		author = "PEiD"
		description = "Wise Installer Stub 1.10.1029.1"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 8B EC 81 EC 40 0F 00 00 53 56 57 6A 04 FF 15 F4 30 40 00 FF 15 74 30 40 00 8A 08 89 45 E8 80 F9 22 75 48 8A 48 01 40 89 45 E8 33 F6 84 C9 74 0E 80 F9 22 74 09 8A 48 01 40 89 45 E8 EB EE 80 38 22 75 04 40 89 45 E8 80 38 20 75 09 40 80 38 20 74 FA 89 45 E8 8A 08 80 F9 2F 74 2B 84 C9 74 1F 80 F9 3D 74 1A 8A 48 01 40 EB F1 33 F6 84 C9 74 D6 80 F9 20 74 }
	condition:
		$a0
}

rule wzip_sfx_6
{
	meta:
		author = "PEiD"
		description = "WinZip 32-bit SFX 6.x module"
		group = "190"
		function = "0"
	strings:
		$a0 = { FF 15 ?? ?? ?? ?? B1 22 38 08 74 02 B1 20 40 80 38 ?? 74 10 38 08 74 06 40 80 38 ?? 75 F6 80 38 ?? 74 01 40 33 C9 ?? ?? ?? ?? FF 15 }
	condition:
		$a0 at pe.entry_point
}

rule wzip_sfx_8
{
	meta:
		author = "PEiD"
		description = "WinZip 32-bit SFX 8.x module"
		group = "190"
		function = "0"
	strings:
		$a0 = { 53 FF 15 ?? ?? ?? ?? B3 22 38 18 74 03 80 C3 FE 8A 48 01 40 33 D2 3A CA 74 0A 3A CB 74 06 8A 48 01 40 EB F2 38 10 }
	condition:
		$a0 at pe.entry_point
}

rule mscab_sfx
{
	meta:
		author = "PEiD"
		description = "Microsoft CAB SFX module"
		group = "29"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 EC 44 56 FF 15 ?? 10 ?? 01 8B F0 8A 06 3C 22 75 }
	condition:
		$a0
}

rule wwpack1x
{
	meta:
		author = "PEiD"
		description = "WWPack32 1.x -> Piotr Warezak"
		group = "191"
		function = "0"
	strings:
		$a0 = { 53 55 8B E8 33 DB EB 60 }
	condition:
		$a0
}

rule xlock11
{
	meta:
		author = "PEiD"
		description = "XCR 0.11 -> X-Lock"
		group = "192"
		function = "0"
	strings:
		$a0 = { 60 8B F0 33 DB 83 C3 01 83 C0 01 }
	condition:
		$a0 at pe.entry_point
}

rule xlock12
{
	meta:
		author = "PEiD"
		description = "XCR 0.12 -> X-Lock"
		group = "192"
		function = "0"
	strings:
		$a0 = { 60 9C E8 ?? ?? ?? ?? 8B DD 5D 81 ED ?? ?? ?? ?? 89 9D }
	condition:
		$a0 at pe.entry_point
}

rule xcr013
{
	meta:
		author = "PEiD"
		description = "XCR 0.13 -> X-Lock"
		group = "192"
		function = "0"
	strings:
		$a0 = { 93 71 08 ?? ?? ?? ?? ?? ?? ?? ?? 8B D8 78 E2 ?? ?? ?? ?? 9C 33 C3 ?? ?? ?? ?? 60 79 CE ?? ?? ?? ?? E8 01 ?? ?? ?? ?? 83 C4 04 E8 AB FF FF FF ?? ?? ?? ?? 2B E8 ?? ?? ?? ?? 03 C5 FF 30 ?? ?? ?? ?? C6 ?? EB }
	condition:
		$a0
}

rule xpeor99b
{
	meta:
		author = "PEiD"
		description = "X-PEOR 0.99b -> MadMax"
		group = "193"
		function = "0"
	strings:
		$a0 = { E8 ?? ?? ?? ?? 5D 8B CD 81 ED 7A 29 40 ?? 89 AD 0F 6D 40 }
	condition:
		$a0 at pe.entry_point
}

rule xprot
{
	meta:
		author = "PEiD"
		description = "Xtreme-Protector 1.00 - 1.05 -> Rafael Ahucha & Sergio Lara"
		group = "194"
		function = "0"
	strings:
		$a0 = { E8 ?? ?? ?? ?? 5D 81 ?? ?? ?? ?? ?? 6A 45 E8 A3 ?? ?? ?? 68 ?? ?? ?? ?? E8 }
	condition:
		$a0
}

rule xprot106
{
	meta:
		author = "PEiD"
		description = "Xtreme-Protector 1.06 -> Rafael Ahucha & Sergio Lara"
		group = "194"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 05 ?? ?? ?? E9 4A 01 ?? ?? 60 8B 74 24 24 8B 7C 24 28 FC B2 80 8A 06 46 88 07 47 BB 02 ?? ?? ?? 02 D2 75 05 8A 16 46 12 D2 73 EA 02 D2 75 05 8A 16 46 12 D2 73 4F 33 C0 02 D2 75 05 8A 16 46 12 D2 0F 83 DF ?? ?? ?? 02 D2 75 05 }
	condition:
		$a0 at pe.entry_point
}

rule xprot107
{
	meta:
		author = "PEiD"
		description = "Xtreme-Protector 1.07 -> Rafael Ahucha & Sergio Lara"
		group = "194"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 1E 00 00 00 E8 00 00 00 00 58 2D 16 00 00 00 B9 79 01 00 00 C6 00 E9 83 E9 05 89 48 01 E9 4A 01 00 00 60 8B 74 24 24 8B 7C 24 28 }
	condition:
		$a0 at pe.entry_point
}

rule yc1
{
	meta:
		author = "PEiD"
		description = "yoda's cryptor 1.0"
		group = "195"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED E7 1A 40 ?? E8 A1 ?? ?? ?? E8 D1 ?? ?? ?? E8 85 01 ?? ?? F7 85 }
	condition:
		$a0 at pe.entry_point
}

rule yc11
{
	meta:
		author = "PEiD"
		description = "yoda's cryptor 1.1"
		group = "195"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 8A 1C 40 ?? B9 9E ?? ?? ?? 8D BD 4C 23 40 ?? 8B F7 33 }
	condition:
		$a0 at pe.entry_point
}

rule yc12
{
	meta:
		author = "PEiD"
		description = "yoda's cryptor 1.2"
		group = "195"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED F3 1D 40 ?? B9 7B 09 ?? ?? 8D BD 3B 1E 40 ?? 8B F7 AC }
	condition:
		$a0 at pe.entry_point
}

rule yc_gen
{
	meta:
		author = "PEiD"
		description = "yoda's cryptor 1.x / modified"
		group = "195"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? B9 ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 8B F7 AC }
	condition:
		$a0 at pe.entry_point
}

rule yp10
{
	meta:
		author = "PEiD"
		description = "yoda's Protector 1.0b -> Ashkbiz Danehkar"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 4C 32 40 00 E8 03 00 00 00 EB 01 ?? B9 EA 47 40 00 81 E9 E9 32 40 00 8B D5 81 C2 E9 32 40 00 8D 3A 8B F7 33 C0 E8 04 00 00 00 90 EB 01 ?? E8 03 00 00 00 EB 01 }
	condition:
		$a0
}

rule yp101
{
	meta:
		author = "PEiD"
		description = "yoda's Protector 1.01 -> Ashkbiz Danehkar"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 8B EC 53 56 57 E8 03 00 00 00 EB 01 ?? E8 86 00 00 00 E8 03 00 00 00 EB 01 ?? E8 79 00 00 00 E8 03 00 00 00 EB 01 ?? E8 A4 00 00 00 E8 03 00 00 00 EB 01 ?? E8 97 00 00 00 E8 03 00 00 00 EB 01 ?? E8 2D 00 00 00 E8 03 00 00 00 EB 01 ?? 60 E8 00 00 00 00 5D 81 ED A5 E5 41 00 8B D5 81 C2 F3 E5 41 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? B9 F0 FE 41 00 81 E9 93 E6 41 00 8B D5 81 C2 93 E6 41 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 33 C0 64 FF 30 64 89 20 CC C3 90 EB 01 ?? AC }
	condition:
		$a0
}

rule yp102
{
	meta:
		author = "PEiD"
		description = "yoda's Protector 1.02 -> Ashkbiz Danehkar"
		group = "444"
		function = "0"
	strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2E E8 03 00 00 00 EB 01 ?? C3 60 E8 00 00 00 00 5D 81 ED 23 3F 42 00 8B D5 81 C2 72 3F 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 35 66 42 00 81 E9 1D 40 42 00 8B D5 81 C2 1D 40 42 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 BE 1F 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 90 EB 01 ?? AC }
	condition:
		$a0 at pe.entry_point
}

rule yp102dll
{
	meta:
		author = "PEiD"
		description = "yoda's Protector 1.02 DLL/OCX -> Ashkbiz Danehkar"
		group = "444"
		function = "0"
	strings:
		$a0 = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 60 E8 00 00 00 00 5D 81 ED 23 3F 42 00 8B D5 81 C2 72 3F 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 35 66 42 00 81 E9 1D 40 42 00 8B D5 81 C2 1D 40 42 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 BE 1F 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 90 EB 01 ?? AC }
	condition:
		$a0 at pe.entry_point
}

rule yp1032
{
	meta:
		author = "PEiD"
		description = "yoda's Protector 1.03.2 -> Ashkbiz Danehkar"
		group = "444"
		function = "0"
	strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2E E8 03 00 00 00 EB 01 ?? C3 60 E8 00 00 00 00 5D 81 ED 94 73 42 00 8B D5 81 C2 E3 73 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 BF A4 42 00 81 E9 8E 74 42 00 8B D5 81 C2 8E 74 42 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 63 29 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 90 EB 01 ?? AC }
	condition:
		$a0 at pe.entry_point
}

rule yp1032dll
{
	meta:
		author = "PEiD"
		description = "yoda's Protector 1.03.2 DLL/OCX -> Ashkbiz Danehkar"
		group = "444"
		function = "0"
	strings:
		$a0 = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 60 E8 00 00 00 00 5D 81 ED 94 73 42 00 8B D5 81 C2 E3 73 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 BF A4 42 00 81 E9 8E 74 42 00 8B D5 81 C2 8E 74 42 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 63 29 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 90 EB 01 ?? AC }
	condition:
		$a0 at pe.entry_point
}

rule yp1033
{
	meta:
		author = "PEiD"
		description = "yoda's Protector 1.03.3 -> Ashkbiz Danehkar"
		group = "444"
		function = "0"
	strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8E 00 00 00 E8 03 00 00 00 EB 01 ?? E8 81 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B7 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AA 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2D E8 03 00 00 00 EB 01 ?? 60 E8 00 00 00 00 5D 81 ED 07 E2 40 00 8B D5 81 C2 56 E2 40 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 4B 0C 41 00 81 E9 01 E3 40 00 8B D5 81 C2 01 E3 40 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 9C 22 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 CC CC CC CC AC }
	condition:
		$a0
}

rule yp1033dll
{
	meta:
		author = "PEiD"
		description = "yoda's Protector 1.03.3 -> Ashkbiz Danehkar"
		group = "444"
		function = "0"
	strings:
		$a0 = { 60 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 00 00 00 00 5D 81 ED 07 E2 40 00 8B D5 81 C2 56 E2 40 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 4B 0C 41 00 81 E9 01 E3 40 00 8B D5 81 C2 01 E3 40 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 9C 22 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 CC CC CC CC AC }
	condition:
		$a0
}

rule yp13
{
	meta:
		author = "PEiD"
		description = "yoda's Protector 1.3 -> Ashkbiz Danehkar"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 6C 28 40 ?? B9 5D 34 40 ?? 81 E9 C6 28 40 ?? 8B D5 81 C2 C6 28 40 ?? 8D 3A 8B F7 33 C0 EB 04 90 EB 01 }
	condition:
		$a0
}

rule zcode
{
	meta:
		author = "PEiD"
		description = "ZCode 1.01 -> Giuliano Bertoletti"
		group = "196"
		function = "0"
	strings:
		$a0 = { E9 12 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E9 FB FF FF FF C3 68 ?? ?? ?? ?? 64 FF 35 }
	condition:
		$a0
}

/*
- Clashes with Thinstall 2.5xx -> Jitit Inc ...
[zinc2]

55 8B EC B8 FE 77 9F 11 BB BA ED 6F AB 50 E8 00 00 00
00 58 2D A7 1A 00 00 B9 6C 1A 00 00 BA 20 1B 00 00 BE
00 10 00 00 BF B0 53 00 00 BD EC 1A 00 00 03 E8 81 75
00 42 9C B2 18 81 75 04 40 7E 2B F4 81 75 08 3E 36 26
D0 81 75 0C 3C C4 30 AB 81 75 10 3A 28 D9 29 03 8A 9F
62 1B B0 7D D3 A9 6E BD E3 5B 12 EF DB C2 E1 29 CC 2D
39 03 D8 3B F1 7C 04 3B F2 7C 02 89 2E 83 C6 04 3B F7
7C E3 58 50 68 00 00 40 00 68 80 5A 00 00 12 C4 DC 3F
27 34 34 69 25 0A EA 10

name     = Zinc? 2 -> SWF2EXE
hardcore = 0
group    = 444
*/
rule zeroc
{
	meta:
		author = "PEiD"
		description = "PE-Crypter -> Zero Coder"
		group = "197"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D EB 26 }
	condition:
		$a0
}

rule zipworx
{
	meta:
		author = "PEiD"
		description = "ZipWorx"
		group = "444"
		function = "0"
	strings:
		$a0 = { E9 B8 00 00 00 ?? ?? 45 00 50 00 45 00 54 00 45 00 00 00 00 00 00 22 00 00 B4 01 45 00 ?? ?? 00 00 53 65 63 75 72 65 45 58 45 20 45 78 65 63 75 74 61 62 6C 65 20 46 69 6C 65 20 50 72 6F 74 65 63 74 6F 72 0D 0A 43 6F 70 79 72 69 67 68 74 28 63 29 20 32 30 30 34 2D 32 30 30 37 20 5A 69 70 57 4F 52 58 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 2C 20 4C 4C 43 0D 0A 50 6F 72 74 69 6F 6E 73 20 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 37 2D 32 30 30 31 20 4C 65 65 20 48 61 73 69 75 6B 0D 0A 41 6C 6C 20 52 69 67 68 74 73 20 52 65 73 65 72 76 65 64 2E 0D 0A 00 00 8B 44 24 04 23 05 E3 00 45 00 50 E8 5C 02 00 00 83 C4 04 FE 05 8E 01 45 00 0B C0 74 02 FF E0 8B E5 5D C2 0C 00 80 3D 8E 01 45 00 00 75 13 50 2B C0 50 E8 35 02 00 00 83 C4 04 58 FE 05 8E 01 45 00 C3 94 9A 8D 91 9A 93 CC CD 00 B8 93 90 9D 9E 93 BE 93 93 90 9C 00 B8 93 90 9D 9E 93 B9 8D 9A 9A 00 B8 9A 8B B2 90 9B 8A 93 9A B7 9E 91 9B 93 9A BE 00 B8 9A 8B B2 90 9B 8A 93 9A B9 96 93 9A B1 9E 92 9A BE 00 BC 8D 9A 9E 8B 9A B9 96 93 9A BE 00 BC 8D 9A 9E 8B 9A B9 96 93 9A B2 9E 8F 8F 96 91 98 BE 00 B2 9E 8F A9 96 9A 88 B0 99 B9 96 93 9A 00 AA 91 92 9E 8F A9 96 9A 88 B0 99 B9 96 93 9A 00 BC 93 90 8C }
	condition:
		$a0
}

rule punisher_15
{
	meta:
		author = "PEiD"
		description = "PUNiSHER 1.5 (DEMO) -> FEUERRADER/AHTeam"
		group = "444"
		function = "0"
	strings:
		$a0 = { EB 04 83 A4 BC CE 60 EB 04 80 BC 04 11 E8 00 00 00 00 81 2C 24 CA C2 41 00 EB 04 64 6B 88 18 5D E8 00 00 00 00 EB 04 64 6B 88 18 81 2C 24 86 00 00 00 EB 04 64 6B 88 18 8B 85 9C C2 41 00 EB 04 64 6B 88 18 29 04 24 EB 04 64 6B 88 18 EB 04 64 6B 88 18 8B 04 24 EB 04 64 6B 88 18 89 85 9C C2 41 00 EB 04 64 6B 88 18 58 68 9F 6F 56 B6 50 E8 5D 00 00 00 EB FF 71 78 C2 50 00 EB D3 5B F3 68 89 5C 24 48 5C 24 58 FF 8D 5C 24 58 5B 83 C3 4C 75 F4 5A 8D 71 78 75 09 81 F3 EB FF 52 BA 01 00 83 EB FC 4A FF 71 0F 75 19 8B 5C 24 00 00 81 33 50 53 8B 1B 0F FF C6 75 1B 81 F3 EB 87 1C 24 8B 8B 04 24 83 EC FC EB 01 E8 83 EC FC E9 E7 00 00 00 58 EB FF F0 EB FF C0 83 E8 FD EB FF 30 E8 C9 00 00 00 89 E0 EB FF D0 EB FF 71 0F 83 C0 01 EB FF 70 F0 71 EE EB FA EB 83 C0 14 EB FF 70 ED }
	condition:
		$a0
}

rule fu_njoy
{
	meta:
		author = "PEiD"
		description = "Fuck'n'Joy 1.0c -> UsAr"
		group = "444"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED D8 05 40 00 FF 74 24 20 E8 8C 02 00 00 0B C0 0F 84 2C 01 00 00 89 85 6C 08 40 00 8D 85 2F 08 40 00 50 FF B5 6C 08 40 00 E8 EF 02 00 00 0B C0 0F 84 0C 01 00 00 89 85 3B 08 40 00 8D 85 3F 08 40 00 50 FF B5 6C 08 40 00 E8 CF 02 00 00 0B C0 0F 84 EC 00 00 00 89 85 4D 08 40 00 8D 85 51 08 40 00 50 FF B5 6C 08 40 00 E8 AF 02 00 00 0B C0 0F 84 CC 00 00 00 89 85 5C 08 40 00 8D 85 67 07 40 00 E8 7B 02 00 00 8D B5 C4 07 40 00 56 6A 64 FF 95 74 07 40 00 46 80 3E 00 75 FA C7 06 74 6D 70 2E 83 C6 04 C7 06 65 78 65 00 8D 85 36 07 40 00 E8 4C 02 00 00 33 DB 53 53 6A 02 53 53 68 00 00 00 40 8D 85 C4 07 40 00 50 FF 95 74 07 40 00 89 85 78 07 40 00 8D 85 51 07 40 00 E8 21 02 00 00 6A 00 8D 85 7C 07 40 00 50 68 00 ?? ?? 00 8D 85 F2 09 40 00 50 FF }
	condition:
		$a0
}

rule winrar_sfx_320
{
	meta:
		author = "PEiD"
		description = "WinRAR 32-bit SFX 3.20 module"
		group = "444"
		function = "0"
	strings:
		$a0 = { E9 D3 18 00 00 00 00 00 00 90 90 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 DD 30 41 00 6A 00 6A 00 8B C6 8B CF E8 32 42 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 C8 19 01 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 EB 30 68 80 00 00 00 68 98 40 41 00 6A 65 56 E8 }
	condition:
		$a0
}

rule RARSFX
{
	meta:
		author = "PEiD"
		description = "RAR SFX"
		group = "444"
		function = "0"
	strings:
		$a0 = { E9 27 17 00 00 00 00 00 00 90 90 90 55 8B EC 50 B8 02 00 00 00 81 C4 04 F0 FF FF 50 48 75 F6 81 C4 F0 F1 FF FF 8B 45 FC 53 56 57 8B 7D 10 8B 75 0C 8B 5D 08 8B D6 FF 75 14 68 01 21 41 00 6A 00 6A 00 8B C3 8B CF E8 7D 40 00 00 81 EE 10 01 00 00 74 0C 4E 0F 84 F1 02 00 00 E9 A1 05 00 00 89 1D 5C 28 41 00 89 1D 60 28 41 00 83 3D 0C 39 41 00 00 74 13 FF 35 0C 39 41 00 6A 01 68 80 00 00 00 53 E8 41 0D 01 00 83 3D 10 39 41 00 00 74 15 FF 35 10 39 41 00 6A 00 68 72 01 00 00 6A 69 53 E8 1D 0D 01 00 6A 67 53 E8 8B 0C 01 00 8B F8 8D 45 EC 50 57 E8 }
	condition:
		$a0
}

rule drweb
{
	meta:
		author = "PEiD"
		description = "Dr.Web Virus-Finding Engine -> InSoft EDV-Systeme"
		group = "444"
		function = "0"
	strings:
		$a0 = { B8 01 00 00 00 C2 0C 00 8D 80 00 00 00 00 8B D2 8B ?? 24 04 }
	condition:
		$a0
}

rule upxshit_500mhz
{
	meta:
		author = "PEiD"
		description = "UPX-Shit 0.1 -> 500mhz"
		group = "444"
		function = "0"
	strings:
		$a0 = { E8 00 00 00 00 5E 83 C6 14 AD 89 C7 AD 89 C1 AD 30 07 47 E2 FB AD FF E0 C3 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 55 50 58 2D 53 68 69 74 20 76 30 2E 31 20 2D 20 77 77 77 2E 62 6C 61 63 6B 6C 6F 67 69 63 2E 6E 65 74 20 2D 20 63 6F 64 65 20 62 79 20 5B 35 30 30 6D 68 7A 5D }
	condition:
		$a0
}

rule exeshield_cryptor13
{
	meta:
		author = "PEiD"
		description = "ExeShield Cryptor 1.3"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 8C 21 40 00 B9 51 2D 40 00 81 E9 E6 21 40 00 8B D5 81 C2 E6 21 40 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC }
	condition:
		$a0
}

rule slvprot06
{
	meta:
		author = "PEiD"
		description = "SLVc0deProtector 0.6 -> SLV"
		group = "444"
		function = "0"
	strings:
		$a0 = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 00 00 93 E8 31 00 00 00 78 E8 DD FF FF FF 38 E8 E3 FF FF FF 66 E8 0D 00 00 00 04 E8 E3 FF FF FF 70 E8 CB FF FF FF 69 E8 DD FF FF FF 58 E8 DD FF FF FF 69 E8 E3 FF FF FF 79 E8 BF FF FF FF 69 83 C4 40 E8 00 00 00 00 5D 81 ED 97 11 40 00 8D B5 EF 11 40 00 B9 FE 2D 00 00 8B FE AC F8 ?? ?? ?? ?? ?? ?? 90 }
	condition:
		$a0
}

rule slvprot061
{
	meta:
		author = "PEiD"
		description = "SLVc0deProtector 0.61 -> SLV"
		group = "444"
		function = "0"
	strings:
		$a0 = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02 FA 04 E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 00 00 93 E8 31 00 00 00 78 E8 DD FF FF FF 38 E8 E3 FF FF FF 66 E8 0D 00 00 00 04 E8 E3 FF FF FF 70 E8 CB FF FF FF 69 E8 DD FF FF FF 58 E8 DD FF FF FF 69 E8 E3 FF FF FF 79 E8 BF FF FF FF 69 83 C4 40 E8 00 00 00 00 5D 81 ED 9D 11 40 00 8D 95 B4 11 40 00 E8 CB 2E 00 00 33 C0 F7 F0 69 8D B5 05 12 40 }
	condition:
		$a0
}

rule yodaprot_1033_exe
{
	meta:
		author = "PEiD"
		description = "yoda's Protector 1.03.3 (exe/scr/com) -> Ashkbiz Danehkar"
		group = "444"
		function = "0"
	strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8E 00 00 00 E8 03 00 00 00 EB 01 ?? E8 81 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B7 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AA 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2D E8 03 00 00 00 EB 01 ?? 60 E8 00 00 00 00 5D 81 ED 07 E2 40 00 8B D5 81 C2 56 E2 40 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 }
	condition:
		$a0
}

rule yodaprot_1033_dllocx
{
	meta:
		author = "PEiD"
		description = "yoda's Protector 1.03.3 (dll/ocx) -> Ashkbiz Danehkar"
		group = "444"
		function = "0"
	strings:
		$a0 = { 60 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 00 00 00 00 5D 81 ED 07 E2 40 00 8B D5 81 C2 56 E2 40 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 }
	condition:
		$a0
}

rule winupack_038
{
	meta:
		author = "PEiD"
		description = "Upack 0.38 -> Dwing"
		group = "444"
		function = "0"
	strings:
		$a0 = { 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 38 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 ?? 00 00 ?? 00 00 ?? 00 00 ?? ?? 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? ?? 14 00 00 00 00 ?? ?? ?? ?? ?? ?? 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 }
	condition:
		$a0
}

rule winupack_039_final
{
	meta:
		author = "PEiD"
		description = "Upack 0.39 final -> Dwing"
		group = "444"
		function = "0"
	strings:
		$a0 = { 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 39 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 ?? 00 00 ?? 00 00 ?? 00 00 ?? ?? 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? ?? 14 00 00 00 00 ?? ?? ?? ?? ?? ?? 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 }
	condition:
		$a0
}

rule themida_1201
{
	meta:
		author = "PEiD"
		description = "Themida 1.2.0.1 (compressed) -> Oreans Technologies"
		group = "444"
		function = "0"
	strings:
		$a0 = { B8 00 00 ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 ?? ?? ?? 00 03 C7 B9 ?? ?? ?? 00 03 CF EB 0A B8 ?? ?? ?? ?? B9 5A ?? ?? ?? 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D 26 00 00 00 B9 EF 01 00 00 C6 00 E9 83 E9 05 89 }
	condition:
		$a0
}

rule slvprot11
{
	meta:
		author = "PEiD"
		description = "SLVc0deProtector 1.1 -> SLV"
		group = "444"
		function = "0"
	strings:
		$a0 = { E8 00 00 00 00 58 C6 00 EB C6 40 01 08 FF E0 E9 4C }
	condition:
		$a0
}

rule purebasic
{
	meta:
		author = "PEiD"
		description = "PureBasic -> Neil Hodgson - needs to be added"
		group = "444"
		function = "0"
	strings:
		$a0 = { 6A 00 ?? ?? ?? ?? ?? A3 ?? ?? 41 00 E8 ?? ?? ?? 00 6A 0A 50 6A 00 FF 35 ?? ?? 41 00 E8 07 00 00 00 50 E8 ?? ?? ?? 00 CC 68 ?? 00 00 00 68 00 00 00 00 68 ?? ?? 41 00 E8 ?? ?? 00 00 83 C4 0C 8B 44 24 04 A3 ?? ?? 41 00 68 00 00 00 00 68 A0 0F 00 00 68 00 00 00 00 E8 }
	condition:
		$a0
}

rule mucruncher
{
	meta:
		author = "PEiD"
		description = "MuCruncher -> Epilogue"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 44 51 40 00 E8 68 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 44 51 40 00 E8 48 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 5C 51 40 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 50 51 40 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 53 83 EC 24 C7 04 24 80 11 40 00 E8 7D 15 00 00 83 EC 04 E8 E5 0F 00 00 C7 04 24 00 30 40 00 8B 15 10 30 40 00 8D 4D F8 C7 45 F8 00 00 00 00 89 4C 24 10 89 54 }
	condition:
		$a0
}

rule iworm
{
	meta:
		author = "PEiD"
		description = "WARNING -> VIRUS -> I-Worm HYBRIS"
		group = "800"
		function = "0"
	strings:
		$a0 = { EB 16 A8 54 ?? ?? 47 41 42 4C 4B 43 47 43 ?? ?? ?? ?? ?? ?? 52 49 53 ?? FC 68 4C 70 40 ?? FF 15 }
	condition:
		$a0 at pe.entry_point
}

rule msvcspx1
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 6.0 SPx Method 1"
		group = "15"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 EC 44 56 FF 15 ?? ?? ?? ?? 8B F0 8A ?? 3C 22 }
	condition:
		$a0 at pe.entry_point
}

/*
[ms_vb5]

68 ?? ?? ?? ?? E8 ?? FF FF FF ?? ?? ?? ?? ?? ??
30

name     = Microsoft Visual Basic 5.0 / 6.0
hardcore = 0
group    = 79

[ms_vbx]

68 ?? ?? ?? ?? E8 ?? FF FF FF

name     = Microsoft Visual Basic 5.0 - 6.0
hardcore = 0
group    = 79
*/
rule msvcspx2
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 6.0 SPx Method 2"
		group = "15"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 EC 44 56 FF 15 ?? ?? ?? ?? 6A 01 8B F0 FF 15 }
	condition:
		$a0 at pe.entry_point
}

rule msvc70
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 7.0"
		group = "444"
		function = "0"
	strings:
		$a0 = { 6A 0C 68 88 BF 01 10 E8 B8 1C 00 00 33 C0 40 89 45 E4 8B 75 0C 33 FF 3B F7 75 0C 39 3D 6C 1E 12 10 0F 84 B3 00 00 00 89 7D FC 3B F0 74 05 83 FE 02 75 31 A1 98 36 12 10 3B C7 74 0C FF 75 10 56 }
	condition:
		$a0
}

rule msvc71_dll
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 7.1 DLL"
		group = "444"
		function = "0"
	strings:
		$a0 = { 6A 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 40 89 45 E4 }
	condition:
		$a0
}

rule msvc80_dll
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 8.0 DLL"
		group = "444"
		function = "0"
	strings:
		$a0 = { 6A 10 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 FF 47 89 7D E4 }
	condition:
		$a0
}

rule telock10p
{
	meta:
		author = "PEiD"
		description = "tElock 1.0 (private) -> tE!"
		group = "444"
		function = "0"
	strings:
		$a0 = { E9 ?? ?? FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 }
	condition:
		$a0
}

rule vprotector_12
{
	meta:
		author = "PEiD"
		description = "vprotector 1.2 -> vcasm"
		group = "444"
		function = "0"
	strings:
		$a0 = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D 00 E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 74 F3 75 F1 EB 24 64 FF 35 00 00 00 00 EB 12 FF 9C 74 03 75 01 E9 81 0C 24 00 01 00 00 9D 90 EB F4 64 89 25 00 00 00 00 EB E6 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 33 F6 E8 10 00 00 00 8B }
	condition:
		$a0
}

rule exefog_112
{
	meta:
		author = "PEiD"
		description = "EXEFog 1.12"
		group = "444"
		function = "0"
	strings:
		$a0 = { E8 00 00 00 00 5D 83 C5 12 55 C3 20 83 B8 ED 20 37 EF C6 B9 79 37 9E 90 EB 04 01 07 01 07 BB ?? ?? ?? ?? B9 C8 03 00 00 B0 ?? 30 04 0B 8A 04 0B E2 F8 E8 00 00 00 5D DE }
	condition:
		$a0 at pe.entry_point
}

rule fake_ninja_28_private_relase_anti_debugging
{
	meta:
		author = "PEiD"
		description = "Fake Ninja 2.8 Private Release"
		group = "444"
		function = "0"
	strings:
		$a0 = { 0F B6 40 02 83 F8 01 74 FE EB 01 E8 90 C0 FF FF EB 03 BD F4 B5 64 A1 30 00 00 00 0F B6 40 02 74 01 BA 74 E0 50 00 64 A1 30 00 00 00 83 C0 68 8B 00 EB 00 83 F8 70 74 CF EB 02 EB FE 90 90 90 0F 31 33 C9 03 C8 0F 31 2B C1 3D FF 0F 00 00 73 EA E8 08 00 00 00 C1 3D FF 0F 00 00 74 AA EB 07 E8 8B 40 30 EB 08 EA 64 A1 18 00 00 00 EB F2 }
	condition:
		$a0 at pe.entry_point
}

rule kbys_packer_028_beta
{
	meta:
		author = "PEiD"
		description = "KBys Packer 0.28 Beta -> Shoooo"
		group = "444"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5E 83 EE 0A 8B 06 03 C2 8B 08 89 4E F3 83 EE 0F 56 52 8B F0 AD AD 03 C2 8B D8 6A 04 BF 00 10 00 00 57 57 6A 00 FF 53 08 5A 59 BD 00 80 00 00 55 6A 00 50 51 52 50 89 06 AD AD 03 C2 50 AD 03 C2 FF D0 6A 04 57 AD 50 6A 00 FF 53 }
	condition:
		$a0 at pe.entry_point
}

rule kkrunchy_023_alpha
{
	meta:
		author = "PEiD"
		description = "kkrunchy 0.23 alpha -> Ryd"
		group = "444"
		function = "0"
	strings:
		$a0 = { BD 08 ?? ?? 00 C7 45 00 ?? ?? ?? 00 FF 4D 08 C6 45 0C 05 8D 7D 14 31 C0 B4 04 89 C1 F3 AB BF ?? ?? ?? 00 57 BE ?? ?? ?? 00 31 C9 41 FF 4D 0C 8D 9C 8D A0 00 00 00 FF D6 10 C9 73 F3 FF 45 0C 91 AA 83 C9 FF 8D 5C 8D 18 FF D6 74 DD E3 17 8D 5D 1C FF D6 74 10 8D 9D A0 08 00 00 E8 ?? 00 00 00 8B 45 10 EB 42 8D 9D A0 04 00 00 E8 ?? 00 00 00 49 49 78 40 8D 5D 20 74 03 83 C3 40 31 D2 42 E8 ?? 00 00 00 8D 0C 48 F6 C2 10 74 F3 41 91 8D 9D A0 08 00 00 E8 ?? 00 00 00 3D 00 08 00 00 83 D9 FF 83 F8 60 83 D9 FF 89 45 10 56 89 FE 29 C6 F3 A4 5E EB 90 BE ?? ?? ?? 00 BB ?? ?? ?? 00 55 46 AD 85 C0 74 ?? 97 56 FF 13 85 C0 74 16 95 AC 84 C0 75 FB 38 06 74 E8 78 ?? 56 55 FF 53 04 AB 85 C0 }
	condition:
		$a0
}

rule kkrunchy_023_alpha_2
{
	meta:
		author = "PEiD"
		description = "kkrunchy 0.23 alpha 2 -> Ryd"
		group = "444"
		function = "0"
	strings:
		$a0 = { BD ?? ?? ?? ?? C7 45 00 ?? ?? ?? 00 B8 ?? ?? ?? 00 89 45 04 89 45 54 50 C7 45 10 ?? ?? ?? 00 FF 4D 0C FF 45 14 FF 45 58 C6 45 1C 08 B8 00 08 00 00 8D 7D 30 AB AB AB AB BB 00 00 D8 00 BF }
	condition:
		$a0
}

rule mz_crypt_10
{
	meta:
		author = "PEiD"
		description = "MZ_Crypt 1.0 -> BrainSt0rm"
		group = "444"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 25 14 40 00 8B BD 77 14 40 00 8B 8D 7F 14 40 00 EB 28 83 7F 1C 07 75 1E 8B 77 0C 03 B5 7B 14 40 00 33 C0 EB 0C 50 8A A5 83 14 40 00 30 26 58 40 46 3B 47 10 76 EF 83 C7 28 49 0B C9 75 D4 8B 85 73 14 40 00 89 44 24 1C 61 FF E0 }
	condition:
		$a0
}

rule mz0ope_106b
{
	meta:
		author = "PEiD"
		description = "MZ0oPE 1.0.6b -> TaskFall"
		group = "444"
		function = "0"
	strings:
		$a0 = { EB CA 89 03 83 C3 04 87 FE 32 C0 AE 75 FD 87 FE 80 3E FF 75 E2 46 5B 83 C3 04 53 8B 1B 80 3F FF 75 C9 8B E5 61 68 ?? ?? ?? ?? C3 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4C 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 }
	condition:
		$a0
}

rule nspack_37
{
	meta:
		author = "PEiD"
		description = "nSPack 3.7 -> North Star/ Liu Xing Ping"
		group = "444"
		function = "0"
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 8D ?? ?? FF FF 80 39 01 0F 84 42 02 00 00 C6 01 01 8B C5 2B 85 ?? ?? FF FF 89 85 ?? ?? FF FF 01 85 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 06 55 56 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 69 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 67 03 00 00 03 D9 50 53 E8 B0 02 00 00 5E 5D 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 34 01 13 8B 33 03 7B 04 57 51 53 FF B5 }
	condition:
		$a0
}

rule pequake_00
{
	meta:
		author = "PEiD"
		description = "PEQuake 0.06-> forgat"
		group = "444"
		function = "0"
	strings:
		$a0 = { E8 A5 00 00 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 3D ?? ?? 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4A ?? ?? 00 5B ?? ?? 00 6E ?? ?? 00 00 00 00 00 6B 45 72 4E 65 4C 33 32 2E 64 4C 6C 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 ?? ?? 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 00 }
	condition:
		$a0
}

rule private_personal_packer_ppp_102
{
	meta:
		author = "PEiD"
		description = "Private Personal Packer (PPP) 1.0.2 -> ConquestOfTroy"
		group = "444"
		function = "0"
	strings:
		$a0 = { E8 17 00 00 00 E8 68 00 00 00 FF 35 2C 37 00 10 E8 ED 01 00 00 6A 00 E8 2E 04 00 00 E8 41 04 00 00 A3 74 37 00 10 6A 64 E8 5F 04 00 00 E8 30 04 00 00 A3 78 37 00 10 6A 64 E8 4E 04 00 00 E8 1F 04 00 00 A3 7C 37 00 10 A1 74 37 00 10 8B 1D 78 37 00 10 2B D8 8B 0D 7C 37 00 10 2B C8 83 FB 64 73 0F 81 F9 C8 00 00 00 73 07 6A 00 E8 D9 03 00 00 C3 6A 0A 6A 07 6A 00 E8 D3 03 00 00 A3 20 37 00 10 50 6A 00 E8 DE 03 00 00 A3 24 37 00 10 FF 35 20 37 00 10 6A 00 E8 EA 03 00 00 A3 30 37 00 10 FF 35 24 37 00 10 E8 C2 03 00 00 A3 28 37 00 10 8B 0D 30 37 00 10 8B 3D 28 37 00 10 EB 09 49 C0 04 39 55 80 34 39 24 0B C9 }
	condition:
		$a0
}

rule simplepack_10_method_1
{
	meta:
		author = "PEiD"
		description = "SimplePack 1.0 Method 1 -> bagie[TMX]"
		group = "Fixed"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B FA 6A 00 FF 93 5E ?? 00 00 89 C5 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 8B 86 88 00 00 00 09 C0 75 24 8D 83 1A ?? 00 00 50 6A 04 68 00 10 00 00 55 FF 93 6A ?? 00 00 09 C0 74 0B B8 00 ?? ?? 00 89 86 88 00 00 00 }
	condition:
		$a0
}

rule simplepack_111_method_1
{
	meta:
		author = "PEiD"
		description = "SimplePack 1.11 Method 1 -> bagie[TMX]"
		group = "444"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B FA BD 00 00 ?? ?? ?? ?? 3C 8D 74 3D 00 8D BE F8 00 00 00 0F B7 76 06 4E 8B 47 10 09 C0 74 55 0F B7 47 22 09 C0 74 4D 6A 04 68 00 10 00 00 FF 77 10 6A 00 FF 93 38 03 00 00 50 56 57 89 EE 03 77 0C 8B 4F 10 89 C7 89 C8 C1 E9 02 FC F3 A5 89 C1 83 E1 03 F3 A4 5F 5E 8B 04 24 89 EA 03 57 0C E8 3F 01 00 00 58 68 00 40 00 00 FF 77 10 50 FF 93 3C 03 00 00 83 C7 28 4E 75 9E BE ?? ?? ?? ?? 09 F6 0F 84 0C 01 00 00 01 EE 8B 4E 0C 09 C9 0F 84 FF 00 00 00 01 E9 89 CF 57 FF 93 30 03 00 00 09 C0 75 3D 6A 04 68 00 10 00 00 68 00 10 00 00 6A 00 FF 93 38 03 00 00 89 C6 8D 83 6F 02 00 00 57 50 56 FF 93 44 03 00 00 6A 10 6A 00 56 6A 00 FF 93 48 03 00 00 89 E5 }
	condition:
		$a0
}

rule simplepack_111_method_2
{
	meta:
		author = "PEiD"
		description = "SimplePack 1.11 Method 2 -> bagie[TMX]"
		group = "444"
		function = "0"
	strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 89 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 40 00 00 C0 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 EB 01 CD 64 A1 30 00 00 00 EB 01 CD 8B 48 0C E3 6F EB 01 CD 05 AC 00 00 00 EB 01 CD 66 81 38 93 08 EB 01 CD 75 0A EB 01 CD B8 38 FF FF FF EB 14 EB 01 CD 66 81 38 28 0A 75 4A EB 01 CD B8 1A FF FF FF EB 00 EB 01 CD 31 C9 EB 01 CD 51 EB 01 CD 51 EB 01 CD 6A 11 EB 01 CD 6A FE EB 01 CD E8 03 00 00 00 EB 01 CD 83 04 24 18 EB }
	condition:
		$a0
}

rule simplepack_121_method_1
{
	meta:
		author = "PEiD"
		description = "SimplePack 1.21 Method 1 -> bagie[TMX]"
		group = "444"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B FA BD 00 00 ?? ?? ?? ?? 3C 8D 74 3D 00 8D BE F8 00 00 00 0F B7 76 06 4E 8B 47 10 09 C0 74 55 0F B7 47 22 09 C0 74 4D 6A 04 68 00 10 00 00 FF 77 10 6A 00 FF 93 63 03 00 00 50 56 57 89 EE 03 77 0C 8B 4F 10 89 C7 89 C8 C1 E9 02 FC F3 A5 89 C1 83 E1 03 F3 A4 5F 5E 8B 04 24 89 EA 03 57 0C E8 66 01 00 00 58 68 00 40 00 00 FF 77 10 50 FF 93 67 03 00 00 83 C7 28 4E 75 9E BE ?? ?? ?? ?? 09 F6 0F 84 0C 01 00 00 01 EE 8B 4E 0C 09 C9 0F 84 FF 00 00 00 01 E9 89 CF 57 FF 93 57 03 00 00 09 C0 75 3D 6A 04 68 00 10 00 00 68 00 10 00 00 6A 00 FF 93 63 03 00 00 89 C6 8D 83 96 02 00 00 57 50 56 FF 93 6F 03 00 00 6A 10 6A 00 56 6A 00 FF 93 73 03 00 00 89 E5 }
	condition:
		$a0
}

rule simplepack_121_method_2
{
	meta:
		author = "PEiD"
		description = "SimplePack 1.21 Method 2 -> bagie[TMX]"
		group = "444"
		function = "0"
	strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 ?? 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 00 40 00 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 ?? ?? 00 00 04 00 00 00 00 00 00 02 00 00 00 00 00 10 00 00 ?? 00 00 00 00 10 00 00 10 00 00 00 00 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? 00 00 00 00 00 50 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 60 00 00 E0 00 00 00 00 00 00 00 00 00 ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 C0 4B 45 52 4E 45 4C 33 32 }
	condition:
		$a0
}

rule themida_10xx_1800_compressed_engine
{
	meta:
		author = "PEiD"
		description = "Themida 1.0.x.x - 1.8.0.0 (compressed engine) -> Oreans Technologies"
		group = "444"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 5A ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 5A ?? ?? ?? 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D 26 00 00 00 B9 EF 01 00 00 C6 00 E9 83 E9 05 89 48 01 61 E9 AF 01 }
	condition:
		$a0
}

rule themida_10xx_18xx_no_compression
{
	meta:
		author = "PEiD"
		description = "Themida 1.0.x.x - 1.8.x.x (no compression) -> Oreans Technologies"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 C4 D8 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8B DA C7 45 D8 00 00 00 00 8B 45 D8 40 89 45 D8 81 7D D8 80 00 00 00 74 0F 8B 45 08 89 83 ?? ?? ?? ?? FF 45 08 43 EB E1 89 45 DC 61 8B 45 DC C9 C2 04 00 55 8B EC 81 C4 7C FF FF FF 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8D 45 80 8B 5D 08 C7 85 7C FF FF FF 00 00 00 00 8B 8D 7C FF FF FF D1 C3 88 18 41 89 8D 7C FF FF FF 81 BD 7C FF FF FF 80 00 00 00 75 E3 C7 85 7C FF FF FF 00 00 00 00 8D BA ?? ?? ?? ?? 8D 75 80 8A 0E BB F4 01 00 00 B8 AB 37 54 78 D3 D0 8A 0F D3 D0 4B 75 F7 0F AF C3 47 46 8B 8D 7C FF FF FF 41 89 8D 7C FF FF FF 81 F9 80 00 00 00 75 D1 61 C9 C2 04 00 55 8B EC 83 C4 F0 8B 75 08 C7 45 FC 00 00 00 00 EB 04 FF 45 FC 46 80 3E 00 75 F7 BA 00 00 00 00 8B 75 08 8B 7D 0C EB 7F C7 45 F8 00 00 00 00 EB }
	condition:
		$a0 at pe.entry_point
}

rule themida_18xx_19xx
{
	meta:
		author = "PEiD"
		description = "Themida 1.8.x.x - 1.9.x.x -> Oreans Technologies"
		group = "444"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D 37 ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D 26 00 00 00 B9 EF 01 00 00 C6 00 E9 83 E9 05 89 48 01 61 E9 }
	condition:
		$a0
}

rule upack_034_039
{
	meta:
		author = "PEiD"
		description = "Upack 0.34 - 0.399 -> Dwing"
		group = "444"
		function = "0"
	strings:
		$a0 = { 60 E8 09 00 00 00 ?? ?? ?? 00 E9 06 02 00 00 33 C9 5E 87 0E E3 F4 2B F1 8B DE AD 2B D8 AD 03 C3 50 97 AD 91 F3 A5 5E AD 56 91 01 1E AD E2 FB AD 8D 6E 10 01 5D 00 8D 7D 1C B5 ?? F3 AB 5E AD 53 50 51 97 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 B0 01 E3 29 8B D7 2B 55 0C 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 14 93 FF 16 5A 9F 12 C0 D0 E9 74 0E 9E 1A F2 74 E4 B4 00 33 C9 B5 01 FF 56 08 33 C9 FF 66 1C B1 30 8B 5D 0C 03 D1 FF 16 73 4C 03 D1 FF 16 72 19 03 D1 FF 16 72 29 3C 07 B0 09 72 02 B0 0B 50 8B C7 2B 45 0C 8A }
	condition:
		$a0
}

rule upack_035_alpha
{
	meta:
		author = "PEiD"
		description = "Upack 0.35 alpha -> Dwing"
		group = "444"
		function = "0"
	strings:
		$a0 = { 4D 5A 52 4A 66 33 D2 66 81 3A 4D 5A 75 F5 EB 08 50 45 00 00 4C 01 02 00 8B 5A 3C 8B 5C 1A 78 E9 80 01 00 00 E0 00 ?? ?? 0B 01 00 35 4C 6F 61 64 4C 69 62 72 61 72 79 41 }
	condition:
		$a0
}

rule upack_037
{
	meta:
		author = "PEiD"
		description = "UPack 0.37 -> Dwing"
		group = "444"
		function = "0"
	strings:
		$a0 = { BE B0 11 40 00 AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? 00 00 00 40 00 00 10 00 00 00 02 00 00 04 00 00 00 00 00 37 00 04 00 00 00 00 00 00 00 00 ?? ?? 00 00 02 00 00 00 00 00 00 ?? 00 00 00 00 00 ?? 00 00 10 00 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? 00 14 00 00 00 00 ?? ?? 00 ?? ?? 00 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? 00 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 }
	condition:
		$a0
}

rule upack_038
{
	meta:
		author = "PEiD"
		description = "UPack 0.38 -> Dwing"
		group = "444"
		function = "0"
	strings:
		$a0 = { BE B0 11 40 00 AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? 00 00 00 40 00 00 10 00 00 00 02 00 00 04 00 00 00 00 00 38 00 04 00 00 00 00 00 00 00 00 ?? ?? 00 00 02 00 00 00 00 00 00 ?? 00 00 00 00 00 ?? 00 00 ?? 00 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? 00 14 00 00 00 00 ?? ?? 00 ?? ?? 00 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? 00 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 }
	condition:
		$a0
}

rule upackmutanter_01
{
	meta:
		author = "PEiD"
		description = "Upack-Mutanter 0.1 -> Spirit"
		group = "444"
		function = "0"
	strings:
		$a0 = { BE B0 11 40 00 AD EB 3A 76 34 EB 7C 48 01 ?? ?? ?? ?? ?? 6F 61 64 4C 69 62 ?? ?? ?? ?? ?? 00 00 18 10 00 00 10 00 00 00 00 ?? ?? 00 00 00 40 00 00 10 00 00 00 02 00 00 04 00 EB CC 00 00 3A 00 04 00 50 FF 76 34 EB F2 }
	condition:
		$a0
}

rule aspack_heur
{
	meta:
		author = "PEiD"
		description = "ASPack 2.x (without poly) -> Alexey Solodovnikov"
		group = "105"
		function = "0"
	strings:
		$a0 = { 59 0B C9 89 85 ?? ?? ?? ?? 61 75 08 B8 01 ?? ?? ?? C2 0C ?? 68 ?? ?? ?? ?? C3 }
	condition:
		$a0 at pe.entry_point
}

rule brlnd_cmp
{
	meta:
		author = "PEiD"
		description = "Borland Component"
		group = "31"
		function = "0"
	strings:
		$a0 = { E9 ?? ?? ?? FF 8D 40 }
	condition:
		$a0
}

rule mb2x
{
	meta:
		author = "PEiD"
		description = "MoleBox 2.x.x -> Mole Studio"
		group = "198"
		function = "0"
	strings:
		$a0 = { 60 E8 4F 00 00 00 }
	condition:
		$a0
}

rule simupx_single
{
	meta:
		author = "PEiD"
		description = "Simple UPX Cryptor 30.4.2005 [Single Layer] -> MANtiCORE"
		group = "999"
		function = "0"
	strings:
		$a0 = { 60 B8 ?? ?? ?? 00 B9 ?? 01 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? 00 C3 }
	condition:
		$a0
}

rule simupx_multi
{
	meta:
		author = "PEiD"
		description = "Simple UPX Cryptor 30.4.2005 [Multi Layer] -> MANtiCORE"
		group = "999"
		function = "0"
	strings:
		$a0 = { 60 B8 ?? ?? ?? ?? B9 18 00 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? ?? C3 }
	condition:
		$a0
}

rule mew11_12
{
	meta:
		author = "PEiD"
		description = "MEW 11 SE 1.2 -> NorthFox/HCC"
		group = "555"
		function = "0"
	strings:
		$a0 = { 8B DE AD AD 50 AD 97 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 21 B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3E AA EB E0 E8 }
	condition:
		$a0 at pe.entry_point
}

rule beroexepacker_100_dlla
{
	meta:
		author = "PEiD"
		description = "BeRoEXEPacker 1.00 DLL [LZMA] -> BeRo / Farbrausch"
		group = "444"
		function = "0"
	strings:
		$a0 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8B F9 81 FE ?? ?? ?? ?? 7F 10 AC 47 04 18 2C 02 73 F0 29 3E 03 F1 03 F9 EB E8 }
	condition:
		$a0
}

rule beroexepacker_100_dllb
{
	meta:
		author = "PEiD"
		description = "BeRoEXEPacker 1.00 DLL [LZBRS] -> BeRo / Farbrausch"
		group = "444"
		function = "0"
	strings:
		$a0 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC AD 8D 1C 07 B0 80 3B FB 73 3B E8 ?? ?? ?? ?? 72 03 A4 EB F2 E8 ?? ?? ?? ?? 8D 51 FF E8 ?? ?? ?? ?? 56 8B F7 2B F2 F3 A4 5E EB DB 02 C0 75 03 AC 12 C0 C3 33 }
	condition:
		$a0
}

rule beroexepacker_100_dllc
{
	meta:
		author = "PEiD"
		description = "BeRoEXEPacker 1.00 DLL [LZBRR] -> BeRo / Farbrausch"
		group = "444"
		function = "0"
	strings:
		$a0 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC B2 80 33 DB A4 B3 02 E8 ?? ?? ?? ?? 73 F6 33 C9 E8 ?? ?? ?? ?? 73 1C 33 C0 E8 ?? ?? ?? ?? 73 23 B3 02 41 B0 10 }
	condition:
		$a0
}

rule beroexepacker_100a
{
	meta:
		author = "PEiD"
		description = "BeRoEXEPacker 1.00 [LZMA] -> BeRo / Farbrausch"
		group = "444"
		function = "0"
	strings:
		$a0 = { 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 04 00 00 00 8B F9 81 FE ?? ?? ?? ?? 7F 10 AC 47 04 18 2C 02 73 F0 29 3E 03 F1 03 F9 EB E8 BA ?? ?? ?? ?? 8D B2 }
	condition:
		$a0
}

rule beroexepacker_100b
{
	meta:
		author = "PEiD"
		description = "BeRoEXEPacker 1.00 [LZBRS] -> BeRo / Farbrausch"
		group = "444"
		function = "0"
	strings:
		$a0 = { 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC AD 8D 1C 07 B0 80 3B FB 73 3B E8 ?? ?? ?? ?? 72 03 A4 EB F2 E8 ?? ?? ?? ?? 8D 51 FF E8 ?? ?? ?? ?? 56 8B F7 2B F2 F3 A4 5E EB DB 02 C0 75 03 AC 12 C0 C3 33 }
	condition:
		$a0
}

rule beroexepacker_100c
{
	meta:
		author = "PEiD"
		description = "BeRoEXEPacker 1.00 [LZBRR] -> BeRo / Farbrausch"
		group = "444"
		function = "0"
	strings:
		$a0 = { 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B }
	condition:
		$a0
}

rule cryptocracks_pe_protector_092
{
	meta:
		author = "PEiD"
		description = "CRYPToCRACk's PE Protector 0.9.2 -> Lukas Fleischer"
		group = "444"
		function = "0"
	strings:
		$a0 = { E8 01 00 00 00 E8 58 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 37 84 DB 75 33 8B F3 03 ?? ?? 81 3E 50 45 00 00 75 26 }
	condition:
		$a0
}

rule cryptocracks_pe_protector_093
{
	meta:
		author = "PEiD"
		description = "CRYPToCRACk's PE Protector 0.9.3 -> Lukas Fleischer"
		group = "444"
		function = "0"
	strings:
		$a0 = { 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 33 8B F3 03 73 3C 81 3E 50 45 00 00 75 26 0F B7 46 18 8B C8 69 C0 AD 0B 00 00 F7 E0 2D AB 5D 41 4B 69 C9 DE C0 00 00 03 C1 }
	condition:
		$a0
}

rule hmimys_protect_10
{
	meta:
		author = "PEiD"
		description = "hmimys Protect 1.0"
		group = "444"
		function = "0"
	strings:
		$a0 = { E8 BA 00 00 00 ?? 00 00 00 00 ?? ?? 00 00 10 40 00 ?? ?? ?? 00 ?? ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 E7 07 00 00 AD 8B DE 8B F0 83 C3 44 AD 85 C0 74 32 8B F8 56 FF 13 8B E8 AC 84 C0 75 FB AC 84 C0 74 EA 4E AD A9 00 00 00 }
	condition:
		$a0
}

rule inno_installer_405
{
	meta:
		author = "PEiD"
		description = "Inno Installer 4.0.5"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 33 D2 55 68 ?? ?? ?? ?? 64 FF 32 64 89 22 }
	condition:
		$a0
}

rule inno_installer_512
{
	meta:
		author = "PEiD"
		description = "Inno Installer 5.1.2"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 C4 D4 53 56 57 33 C0 89 45 F0 89 45 E4 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 33 D2 55 68 ?? ?? ?? ?? 64 FF 32 64 89 22 }
	condition:
		$a0
}

rule mpack_pe_compressor_002
{
	meta:
		author = "PEiD"
		description = "mPack PE Compressor 0.0.2 -> DeltaAziz"
		group = "444"
		function = "0"
	strings:
		$a0 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 58 ?? ?? ?? 00 00 00 4E ?? ?? 00 00 00 00 00 00 00 00 00 5E ?? ?? 00 4E ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6C ?? ?? 00 7D ?? ?? 00 90 ?? ?? 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 ?? ?? ?? ?? ?? 00 ?? ?? 00 00 ?? ?? 00 00 56 69 72 74 ?? ?? ?? ?? 6C 6C 6F 63 00 00 00 00 00 00 }
	condition:
		$a0
}

rule nspack_33
{
	meta:
		author = "PEiD"
		description = "NsPack 3.3 -> North Star"
		group = "444"
		function = "0"
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 B1 FC FF FF 80 38 00 74 0F 8D 85 D9 FC FF FF 80 38 01 0F 84 42 02 00 00 C6 00 01 8B D5 2B 95 6D FC FF FF 89 95 6D FC FF FF 01 95 9D FC FF FF 8D B5 E1 FC FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 05 FD FF FF 85 C0 0F 84 6A 03 00 00 89 85 95 FC FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD 5D FC FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 01 13 8B 33 03 7B 04 57 51 52 53 FF B5 09 FD FF FF FF B5 05 FD FF FF }
	condition:
		$a0
}

rule nullsoft_install_system_21x
{
	meta:
		author = "PEiD"
		description = "Nullsoft Install System 2.1x"
		group = "444"
		function = "0"
	strings:
		$a0 = { 81 EC ?? ?? ?? ?? 53 55 56 33 F6 57 89 74 24 18 BD ?? ?? ?? ?? C6 44 24 10 20 FF 15 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 56 8D 44 24 30 68 ?? ?? ?? ?? 50 56 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 68 }
	condition:
		$a0
}

rule nullsoft_install_system_2x
{
	meta:
		author = "PEiD"
		description = "Nullsoft Install System 2.x"
		group = "444"
		function = "0"
	strings:
		$a0 = { 83 EC ?? 53 55 56 57 C7 44 24 ?? ?? ?? ?? ?? 33 ?? C6 44 24 ?? 20 FF 15 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? 56 57 A3 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? E8 8D FF FF FF 8B ?? ?? ?? ?? ?? 85 C0 }
	condition:
		$a0
}

rule pelles_c_290_exe_x86_crtlib
{
	meta:
		author = "PEiD"
		description = "Pelles C 2.90 EXE (X86 CRT-LIB)"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC ?? 83 EC ?? 53 56 57 89 65 E8 68 00 00 00 02 E8 ?? ?? ?? ?? 59 A3 }
	condition:
		$a0
}

rule pelles_c_290_300_400_dll_x86_crtlib
{
	meta:
		author = "PEiD"
		description = "Pelles C 2.90, 3.00, 4.00 DLL (X86 CRT-LIB)"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 BF 01 00 00 00 85 DB 75 10 83 3D ?? ?? ?? ?? 00 75 07 31 C0 E9 ?? ?? ?? ?? 83 FB 01 74 05 83 FB 02 75 ?? 85 FF 74 }
	condition:
		$a0
}

rule pelles_c_300_400_450_exe_x86_crtdll
{
	meta:
		author = "PEiD"
		description = "Pelles C 3.00, 4.00, 4.50 EXE (X86 CRT-DLL)"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 E8 C7 45 FC ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 BE ?? ?? ?? ?? EB }
	condition:
		$a0
}

rule pelles_c_300_400_450_exe_x86_crtlib
{
	meta:
		author = "PEiD"
		description = "Pelles C 3.00, 4.00, 4.50 EXE (X86 CRT-LIB)"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 E8 68 00 00 00 02 E8 ?? ?? ?? ?? 59 A3 }
	condition:
		$a0
}

rule rlpack_115116_aplib_043
{
	meta:
		author = "PEiD"
		description = "RLPack 1.15 - 1.16 (aPlib 0.43) -> ap0x"
		group = "444"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 45 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB }
	condition:
		$a0
}

rule rlpack_115116_lzma_430
{
	meta:
		author = "PEiD"
		description = "RLPack 1.15 - 1.16 (LZMA 4.30) -> ap0x"
		group = "444"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 83 01 00 00 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? EB 14 }
	condition:
		$a0
}

rule ucf_upxtagger
{
	meta:
		author = "PEiD"
		description = "uCF UPX-tagger -> ZigD/uCF"
		group = "444"
		function = "0"
	strings:
		$a0 = { EB 01 E8 ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC }
	condition:
		$a0
}

/*
The following were added by me ..
UPX LZMA versions ..
*/
rule thinstall_27x
{
	meta:
		author = "PEiD"
		description = "Thinstall 2.7x -> Jitit"
		group = "444"
		function = "0"
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 58 BB DC 1E 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 50 00 00 68 D8 00 00 00 E8 C1 FE FF FF E9 97 FF FF FF CC CC }
	condition:
		$a0
}

/*
An EP Only one for testing ..  Btw, the orig Upx_1 sig has 24 pointless ?? bytes as it's hardcore ..
Also, it matches the one above it .. :)
*/
rule UPX_293_302_LZMA_BoB
{
	meta:
		author = "PEiD"
		description = "UPX 2.93 - 3.02 [LZMA] -> Markus Oberhumer, Laszlo Molnar & John Reiser"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { 60 BE ?? ?? ?? 00 8D BE ?? ?? ?? ?? 57 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 03 00 02 00 90 90 90 90 90 }
	condition:
		$a0
}

/*
Fixed MoleBox / Pro ..
Orig - 60 E8 4F 00 00 00
*/
rule UPX_EP_ONLY_BoB
{
	meta:
		author = "PEiD"
		description = "UPX 1.xx - 3.xx -> Markus Oberhumer, Laszlo Molnar & John Reiser"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 9C ?? 01 00 01 00 67 93 57 EB 11 90 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 }
	condition:
		$a0
}

/*
Shouldn't be hardcore, unless you like fakers ..  Same for other YC sigs I think :)
*/
rule mb2x_BoB
{
	meta:
		author = "PEiD"
		description = "MoleBox 2.x.x -> Mole Studio"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { E8 00 00 00 00 60 E8 4F 00 00 00 }
	condition:
		$a0
}

/*
Also shouldn't be hardcore ..
*/
rule yc12_BoB
{
	meta:
		author = "PEiD"
		description = "yoda's cryptor 1.2"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED F3 1D 40 ?? B9 7B 09 ?? ?? 8D BD 3B 1E 40 ?? 8B F7 AC }
	condition:
		$a0
}

/*
Also shouldn't be hardcore ..
*/
rule pec168_76_BoB
{
	meta:
		author = "PEiD"
		description = "PECompact 1.68 - 1.84 -> Jeremy Collake"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 ?? 87 DD 8B 85 E6 90 40 ?? 01 85 33 90 40 ?? 66 C7 85 ?? 90 40 ?? 90 90 01 85 DA 90 40 ?? 01 85 DE 90 40 ?? 01 85 E2 90 40 ?? BB 7B 11 }
	condition:
		$a0
}

/*
Also shouldn't be hardcore ..
*/
rule peb20x_BoB
{
	meta:
		author = "PEiD"
		description = "PEBundle 2.0x - 2.4x-> Jeremy Collake"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 83 BD }
	condition:
		$a0
}

/*
Missing from list tho found by PEiD as UltraProtect 1.x -> RISCO Software Inc. ..
*/
rule jdpack_BoB
{
	meta:
		author = "PEiD"
		description = "JDPack 1.x / JDProtect 0.9 -> TLZJ18 Software"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 8B D5 81 ED ?? ?? ?? ?? 2B 95 ?? ?? ?? ?? 81 EA 06 ?? ?? ?? 89 95 ?? ?? ?? ?? 83 BD }
	condition:
		$a0
}

/*
Better Mew 5.0.1 Beta ..
*/
rule ACProtect_14x
{
	meta:
		author = "PEiD"
		description = "ACProtect / ACProtect Pro 1.4x -> RISCO soft"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 90 4D 69 6E 65 49 6D 70 }
	condition:
		$a0 at pe.entry_point
}

/*
This works better for me, there is eXPressor version with push / ret to EP too ..
*/
rule Mew_501
{
	meta:
		author = "PEiD"
		description = "Mew 5.0.1 -> NorthFox / HCC"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { BE 5B 00 40 00 AD 91 AD 93 53 AD 96 56 5F AC C0 C0 ?? 04 ?? C0 C8 ?? AA E2 F4 C3 ?? ?? ?? 00 ?? ?? ?? 00 00 10 40 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D }
	condition:
		$a0
}

/*
Non-hardcore Upx ..
*/
rule expressor150x2
{
	meta:
		author = "PEiD"
		description = "eXPressor 1.5.0.x -> CGSoftLabs"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { EB 01 68 EB 01 ?? ?? ?? ?? 83 EC 0C 53 56 57 EB 01 ?? 83 3D ?? ?? ?? ?? 00 74 08 EB 01 E9 E9 56 01 00 00 EB 02 E8 E9 C7 05 ?? ?? ?? ?? 01 00 00 00 EB 01 C2 E8 E2 05 00 00 EB 02 DA 9F 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF D0 59 59 EB 01 C8 EB 02 66 F0 68 ?? ?? ?? ?? E8 0E 05 00 00 59 EB 01 DD 83 65 F4 00 EB 07 8B 45 F4 40 89 45 F4 83 7D F4 61 73 1F EB 02 DA 1A 8B 45 F4 0F ?? ?? ?? ?? ?? ?? 33 45 F4 8B 4D F4 88 ?? ?? ?? ?? ?? EB 01 EB EB }
	condition:
		$a0 at pe.entry_point
}

rule upx_dll2
{
	meta:
		author = "PEiD"
		description = "UPX 0.80 - 1.24 DLL -> Markus & Laszlo"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB }
	condition:
		$a0
}

rule Upx_193
{
	meta:
		author = "PEiD"
		description = "Upx 1.9x -> Markus & Laszlo"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 28 8B 1E 83 EE FC 11 DB 72 1F 48 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 EB D4 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 EB 52 31 C9 83 E8 03 72 11 C1 E0 08 8A 06 46 }
	condition:
		$a0
}

rule Upx_12x
{
	meta:
		author = "PEiD"
		description = "Upx 1.24 - 1.25 -> Markus & Laszlo"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 8B 1E 83 EE FC 11 DB 72 10 48 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 EB D4 31 C9 83 E8 03 72 11 C1 E0 08 8A 06 46 83 F0 FF 74 78 D1 F8 89 C5 EB 0B 01 DB 75 07 }
	condition:
		$a0
}

rule Upx_123
{
	meta:
		author = "PEiD"
		description = "Upx 1.05 - 1.23 -> Markus & Laszlo"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB ?? EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 8B 1E 83 EE FC 11 DB }
	condition:
		$a0
}

rule DevC5
{
	meta:
		author = "PEiD"
		description = "Dev-C++ 5"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { 55 89 E5 83 EC 14 6A ?? FF 15 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 }
	condition:
		$a0 at pe.entry_point
}

rule CDSSS1B1
{
	meta:
		author = "PEiD"
		description = "CDS SS 1.0 Beta 1 -> CyberDoom / Team-X"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED CA 47 40 00 FF 74 24 20 E8 D3 03 00 00 0B C0 0F 84 13 03 00 00 89 85 B8 4E 40 00 66 8C D8 A8 04 74 0C C7 85 8C 4E 40 00 01 00 00 00 EB 12 64 A1 30 00 00 00 0F B6 40 02 0A C0 0F 85 E8 02 00 00 8D 85 F6 4C 40 00 50 FF B5 B8 4E 40 00 E8 FC 03 00 00 0B C0 0F 84 CE 02 00 00 E8 1E 03 00 00 89 85 90 4E 40 00 8D 85 03 4D 40 00 50 FF B5 B8 }
	condition:
		$a0
}

rule Upack0_1_0_2
{
	meta:
		author = "PEiD"
		description = "Upack 0.1x - 0.2x -> Dwing"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { BE 88 01 ?? ?? AD 8B F8 95 }
	condition:
		$a0
}

rule ASPack212
{
	meta:
		author = "PEiD"
		description = "ASPack 2.12 -> Alexey Solodovnikov"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB }
	condition:
		$a0
}

rule obsidium10069
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.0.0.69 -> Obsidium Software"
		group = "133"
		function = "0"
	strings:
		$a0 = { EB 02 ?? ?? E8 A3 1C }
	condition:
		$a0
}

rule obsidium1110
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.1.1.0 -> Obsidium Software"
		group = "133"
		function = "0"
	strings:
		$a0 = { EB 02 ?? ?? E8 E7 1C }
	condition:
		$a0
}

rule obsidium1114
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.1.1.4 -> Obsidium Software"
		group = "133"
		function = "0"
	strings:
		$a0 = { EB 02 ?? ?? E8 3F 1D 00 00 }
	condition:
		$a0
}

rule Obsidium1_2_5_0
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.2.5.0 -> Obsidium Software"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 0D 33 C0 C3 64 67 FF 36 00 00 64 67 89 26 00 00 50 33 C0 8B 00 C3 E9 FA 00 00 00 E8 D5 FF FF FF 58 64 67 8F 06 00 00 83 C4 04 E8 2B 13 00 00 }
	condition:
		$a0
}

rule Obsidium1_2_5_8
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.2.5.8 -> Obsidium Software"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { EB 01 ?? E8 29 00 00 00 EB 02 ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 01 ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? EB 01 ?? 58 EB 01 ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 01 ?? E8 7B 21 00 00 }
	condition:
		$a0
}

rule Obsidium1_3_0_0
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.3.0.0 -> Obsidium Software"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { EB 04 ?? ?? ?? ?? E8 29 00 00 00 EB 02 ?? ?? EB 01 ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 22 EB 02 ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 01 ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 01 ?? E8 D5 FF FF FF EB 02 ?? ?? EB 03 ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 02 ?? ?? E8 47 26 00 00 }
	condition:
		$a0
}

rule obsidium_1304
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.3.0.4 -> Obsidium Software"
		group = "555"
		function = "0"
	strings:
		$a0 = { EB 02 ?? ?? E8 25 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 01 ?? 33 C0 EB 01 ?? 8B 00 EB 01 ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 01 ?? E8 3B 26 00 00 }
	condition:
		$a0
}

rule Obsidium1_3_0_13
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.3.0.13 -> Obsidium Software"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { EB 01 ?? E8 26 00 00 00 EB 02 ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 21 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 01 ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 02 ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 01 ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 02 ?? ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 03 ?? ?? ?? E8 13 26 00 00 }
	condition:
		$a0
}

rule Obsidium1_3_0_21
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.3.0.21 -> Obsidium Software"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { EB 03 ?? ?? ?? E8 2E 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 02 ?? ?? 50 EB 01 ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 2B 26 00 00 }
	condition:
		$a0
}

rule Obsidium1_3_0_37
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.3.0.37 -> Obsidium Software"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 26 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 01 ?? 58 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? E8 23 27 00 00 }
	condition:
		$a0
}

rule Obsidium1_3_1_1
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.3.1.1 -> Obsidium Software"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { EB 02 ?? ?? E8 27 00 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 22 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 03 ?? ?? ?? C3 EB 01 ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 03 ?? ?? ?? 58 EB 03 ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 }
	condition:
		$a0
}

rule Obsidium1_3_2_2
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.3.2.2 -> Obsidium Software"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { EB 04 ?? ?? ?? ?? E8 2A 00 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 26 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 02 ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 01 ?? EB 01 ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 04 }
	condition:
		$a0
}

rule Obsidium1_3_3_1
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.3.3.1 -> Obsidium Software"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { EB 01 ?? E8 29 00 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 01 ?? EB 04 ?? ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 02 ?? ?? E8 5F 27 00 00 }
	condition:
		$a0
}

rule Obsidium1_3_3_2
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.3.3.2 -> Obsidium Software"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { EB 01 ?? E8 2B 00 00 00 EB 02 ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 02 ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 02 ?? ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 01 ?? 58 EB 01 ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 02 ?? ?? E8 3B 27 00 00 }
	condition:
		$a0
}

rule Obsidium1_3_3_3
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.3.3.3 -> Obsidium Software"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 8B ?? 24 0C EB 01 ?? 83 ?? B8 00 00 00 28 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 58 EB 01 ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 2B 27 00 00 }
	condition:
		$a0
}

rule Obsidium1_3_3_4
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.3.3.4 -> Obsidium Software"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 25 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 02 ?? ?? 33 C0 EB 01 ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 03 ?? ?? ?? 58 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 03 }
	condition:
		$a0
}

rule Obsidium1_3_3_6
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.3.3.6 -> Obsidium Software"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? ?? ?? ?? ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 26 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 50 EB 01 ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 03 ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 }
	condition:
		$a0
}

rule Obsidium1_3_3_7
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.3.3.7 -> Obsidium Software"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { EB 02 ?? ?? E8 2C 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 27 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 01 ?? 50 EB 02 ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? E8 23 27 00 00 }
	condition:
		$a0
}

rule Obsidium_1_3_3_7b
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.3.3.7 (2007.06.23) -> Obsidium Software"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { EB 02 ?? ?? E8 27 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 23 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 01 ?? 50 EB 02 ?? ?? 33 C0 EB 01 ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 04 ?? ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 01 ?? E8 F7 26 00 00 }
	condition:
		$a0
}

rule Obsidium1_3_3_8
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.3.3.8 -> Obsidium Software"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 ?? EB 04 ?? ?? ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 01 ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 57 27 00 00 }
	condition:
		$a0
}

rule Obsidium1_3_3_9
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.3.3.9 -> Obsidium Software"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 28 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 CF 27 00 00 }
	condition:
		$a0
}

rule Obsidium1_3_4_1
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.3.4.1 -> Obsidium Software"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { EB 01 ?? E8 2A 00 00 00 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 21 EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 02 ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 02 ?? ?? E8 C3 27 00 00 }
	condition:
		$a0
}

rule Obsidium1_3_4_2
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.3.4.2 -> Obsidium Software"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 03 ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 01 ?? E8 C3 27 00 00 }
	condition:
		$a0
}

rule Obsidium1_3_5_0
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.3.5.0 -> Obsidium Software"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { EB 03 ?? ?? ?? E8 ?? ?? ?? ?? EB 02 ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 20 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 01 ?? E8 ?? ?? ?? ?? EB 01 ?? EB 02 ?? ?? 58 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 01 ?? E8 }
	condition:
		$a0
}

rule Obsidium1_3_5_2
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.3.5.2 -> Obsidium Software"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 25 EB 03 ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 01 ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 03 ?? ?? ?? E8 }
	condition:
		$a0
}

rule Obsidium1_4_0_0_Beta
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.4.0.0 Beta -> Obsidium Software"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { EB 01 ?? E8 2F 00 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 21 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 01 ?? C3 EB 01 ?? E9 ?? ?? ?? ?? EB 01 ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 }
	condition:
		$a0
}

/*
Generated PEiD internal signatures ..
*/
rule Upack0_399_brute___Dwing
{
	meta:
		author = "PEiD"
		description = "Upack 0.399 -> Dwing"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 3A 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 ?? 00 00 ?? 00 00 ?? 00 00 10 ?? 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? ?? 14 00 00 00 00 ?? ?? ?? ?? ?? ?? 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? ?? ?? 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB 8B 7E 0C 57 51 E9 ?? ?? ?? ?? 56 10 E2 E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 99 59 D1 E8 13 D2 E2 FA 5D 03 EA 45 59 89 6B 08 56 8B F7 2B F5 F3 A4 AC 5E B1 80 AA 3B }
	condition:
		$a0
}

rule Upack0_32beta__Dwing
{
	meta:
		author = "PEiD"
		description = "Upack 0.32 beta -> Dwing"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { BE 88 01 ?? ?? AD 50 ?? ?? AD 91 F3 A5 }
	condition:
		$a0 at pe.entry_point
}

rule Upack0_32beta__Dwing_
{
	meta:
		author = "PEiD"
		description = "Upack 0.32 beta -> Dwing"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { BE 88 01 ?? ?? AD 50 ?? AD 91 ?? F3 A5 }
	condition:
		$a0 at pe.entry_point
}

rule RLP0_7_3_beta__ap0x
{
	meta:
		author = "PEiD"
		description = "RLP 0.7.3.beta -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 2E 72 6C 70 00 00 00 00 00 50 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 E0 }
	condition:
		$a0 at pe.entry_point
}

rule RLPack1_0beta__ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack 1.0 beta -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 8D 64 24 04 8B 6C 24 FC 8D B5 4C 02 00 00 8D 9D 13 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 F9 01 00 00 89 85 48 02 00 00 5B FF B5 48 02 00 00 56 FF D3 83 C4 08 8B B5 48 02 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 83 C0 04 89 85 44 02 00 00 EB 7A 56 FF 95 F1 01 00 00 89 85 40 02 00 00 8B C6 EB 4F 8B 85 44 02 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 44 02 00 00 C7 00 20 20 20 00 EB 06 FF B5 44 02 00 00 FF B5 40 02 00 00 FF 95 F5 01 00 00 89 07 83 C7 04 8B 85 44 02 00 00 EB 01 40 80 38 00 75 FA 40 89 85 44 02 00 00 80 38 00 75 AC EB 01 46 80 3E 00 75 FA 46 40 8B 38 83 C0 04 89 85 44 02 00 00 80 3E 01 75 81 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 48 02 00 00 FF 95 FD 01 00 00 61 68 ?? ?? ?? ?? C3 60 8B 74 24 24 8B 7C }
	condition:
		$a0
}

rule RLPack1_0_beta__ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack 1.0.beta -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 8D 64 24 04 8B 6C 24 FC 8D B5 4C 02 00 00 8D 9D 13 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB }
	condition:
		$a0
}

rule RLPack1_11__ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack 1.11 -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 4A 02 00 00 8D 9D 11 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB }
	condition:
		$a0
}

rule RLPack1_12_1_14_LZMA4_30___ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack 1.12-1.14 (LZMA 4.30) -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? EB ?? 60 }
	condition:
		$a0
}

rule RLPack1_12_1_14_aPlib0_43___ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack 1.12-1.14 (aPlib 0.43) -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF EB 0F FF ?? ?? ?? FF ?? ?? ?? D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB }
	condition:
		$a0
}

rule RLPack1_15_1_17_aPlib0_43___ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack 1.15-1.17 (aPlib 0.43) -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 45 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB }
	condition:
		$a0
}

rule RLPack1_15_1_17_LZMA4_30___ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack 1.15-1.17 (LZMA 4.30) -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 83 01 00 00 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? EB 14 }
	condition:
		$a0
}

rule RLPack1_15_1_17Dll__ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack 1.15-1.17 Dll -> ap0x"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 45 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB }
	condition:
		$a0
}

rule RLPackFullEdition1_1X__ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack FullEdition 1.1X -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 10 }
	condition:
		$a0 at pe.entry_point
}

rule RLPack1_18_aPlib0_43___ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack 1.18 (aPlib 0.43) -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83 BD 0A 04 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 A7 03 00 00 89 85 16 04 00 00 5B FF B5 16 04 00 00 56 FF D3 83 C4 ?? 8B B5 16 04 00 00 8B C6 EB 01 }
	condition:
		$a0
}

rule RLPack1_18_LZMA4_30___ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack 1.18 (LZMA 4.30) -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 21 0B 00 00 8D 9D FF 02 00 00 33 FF E8 9F 01 00 00 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A 00 00 FF 34 37 FF 74 37 04 FF D3 61 83 C7 ?? 83 3C 37 00 75 E6 83 BD 0D 0B 00 00 00 74 0E 83 BD 11 0B 00 00 00 74 05 E8 F6 01 00 00 8D 74 37 04 53 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 AA 0A 00 00 89 85 1D 0B 00 00 5B 60 FF B5 F9 0A 00 00 56 FF B5 1D 0B 00 00 FF D3 61 8B B5 1D 0B 00 00 8B C6 EB 01 }
	condition:
		$a0
}

rule RLPack1_18Dll_LZMA4_30___ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack 1.18 Dll (LZMA 4.30) -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 9F 01 00 00 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A 00 00 FF 34 37 FF 74 37 04 FF D3 61 83 C7 08 83 3C 37 00 75 E6 83 BD 0D 0B 00 00 00 74 0E 83 BD 11 0B 00 00 00 74 05 E8 F6 01 00 00 8D 74 37 04 53 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 AA 0A 00 00 89 85 1D 0B 00 00 5B 60 FF B5 F9 0A 00 00 56 FF B5 1D 0B 00 00 FF D3 61 8B B5 1D 0B 00 00 8B C6 EB 01 }
	condition:
		$a0
}

rule RLPack1_18Dll_aPlib0_43___ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack 1.18 Dll (aPlib 0.43) -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 5C 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83 BD 0A 04 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 A7 03 00 00 89 85 16 04 00 00 5B FF B5 16 04 00 00 56 FF D3 83 C4 ?? 8B B5 16 04 00 00 8B C6 EB 01 }
	condition:
		$a0
}

rule RLPack1_19_aPlib0_43___ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack 1.19 (aPlib 0.43) -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 3C 04 00 00 EB 0C 8B 85 38 04 00 00 89 85 3C 04 00 00 8D B5 60 04 00 00 8D 9D EB 02 00 00 33 FF E8 52 01 00 00 EB 1B 8B 85 3C 04 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD 48 04 00 00 00 74 0E 83 BD 4C 04 00 00 00 74 05 E8 B8 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 D1 03 00 00 89 85 5C 04 00 00 5B FF B5 5C 04 00 00 56 FF D3 83 C4 08 8B B5 5C 04 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 E9 94 00 00 00 56 FF 95 C9 03 00 00 85 C0 0F 84 B4 00 00 00 89 85 54 04 00 00 8B C6 EB 5B 8B 85 58 04 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 58 04 00 00 C7 00 20 20 20 00 EB 06 FF B5 58 04 00 00 FF B5 54 04 00 00 FF 95 CD 03 00 00 85 C0 74 71 89 07 83 C7 04 8B 85 58 04 00 00 EB 01 40 80 38 00 75 FA 40 89 85 58 04 00 00 66 81 78 02 00 80 74 A5 80 38 00 75 A0 EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 80 3E 01 0F 85 63 FF FF FF 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 5C 04 00 00 FF 95 D5 03 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }
	condition:
		$a0
}

rule RLPack1_19Dll_aPlib0_43___ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack 1.19 Dll (aPlib 0.43) -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 89 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 3C 04 00 00 EB 0C 8B 85 38 04 00 00 89 85 3C 04 00 00 8D B5 60 04 00 00 8D 9D EB 02 00 00 33 FF E8 52 01 00 00 EB 1B 8B 85 3C 04 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD 48 04 00 00 00 74 0E 83 BD 4C 04 00 00 00 74 05 E8 B8 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 D1 03 00 00 89 85 5C 04 00 00 5B FF B5 5C 04 00 00 56 FF D3 83 C4 08 8B B5 5C 04 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 E9 94 00 00 00 56 FF 95 C9 03 00 00 85 C0 0F 84 B4 00 00 00 89 85 54 04 00 00 8B C6 EB 5B 8B 85 58 04 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 58 04 00 00 C7 00 20 20 20 00 EB 06 FF B5 58 04 00 00 FF B5 54 04 00 00 FF 95 CD 03 00 00 85 C0 74 71 89 07 83 C7 04 8B 85 58 04 00 00 EB 01 40 80 38 00 75 FA 40 89 85 58 04 00 00 66 81 78 02 00 80 74 A5 80 38 00 75 A0 EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 80 3E 01 0F 85 63 FF FF FF 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 5C 04 00 00 FF 95 D5 03 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }
	condition:
		$a0
}

rule RLPack1_19_LZMA4_30___ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack 1.19 (LZMA 4.30) -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 49 0B 00 00 EB 0C 8B 85 45 0B 00 00 89 85 49 0B 00 00 8D B5 6D 0B 00 00 8D 9D 2F 03 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 DA 0A 00 00 89 85 41 0B 00 00 E8 76 01 00 00 EB 20 60 8B 85 49 0B 00 00 FF B5 41 0B 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 C7 08 83 3C 37 00 75 DA 83 BD 55 0B 00 00 00 74 0E 83 BD 59 0B 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 DA 0A 00 00 89 85 69 0B 00 00 5B 60 FF B5 41 0B 00 00 56 FF B5 69 0B 00 00 FF D3 61 8B B5 69 0B 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 E9 98 00 00 00 56 FF 95 D2 0A 00 00 89 85 61 0B 00 00 85 C0 0F 84 C8 00 00 00 8B C6 EB 5F 8B 85 65 0B 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 65 0B 00 00 C7 00 20 20 20 00 EB 06 FF B5 65 0B 00 00 FF B5 61 0B 00 00 FF 95 D6 0A 00 00 85 C0 0F 84 87 00 00 00 89 07 83 C7 04 8B 85 65 0B 00 00 EB 01 40 80 38 00 75 FA 40 89 85 65 0B 00 00 66 81 78 02 00 80 74 A1 80 38 00 75 9C EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 80 3E 01 0F 85 5F FF FF FF 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 69 0B 00 00 FF 95 DE 0A 00 00 68 00 40 00 00 68 00 20 0C 00 FF B5 41 0B 00 00 FF 95 DE 0A 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }
	condition:
		$a0
}

rule RLPack1_19Dll_LZMA4_30___ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack 1.19 Dll (LZMA 4.30) -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 C7 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 49 0B 00 00 EB 0C 8B 85 45 0B 00 00 89 85 49 0B 00 00 8D B5 6D 0B 00 00 8D 9D 2F 03 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 DA 0A 00 00 89 85 41 0B 00 00 E8 76 01 00 00 EB 20 60 8B 85 49 0B 00 00 FF B5 41 0B 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 C7 08 83 3C 37 00 75 DA 83 BD 55 0B 00 00 00 74 0E 83 BD 59 0B 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 DA 0A 00 00 89 85 69 0B 00 00 5B 60 FF B5 41 0B 00 00 56 FF B5 69 0B 00 00 FF D3 61 8B B5 69 0B 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 E9 98 00 00 00 56 FF 95 D2 0A 00 00 89 85 61 0B 00 00 85 C0 0F 84 C8 00 00 00 8B C6 EB 5F 8B 85 65 0B 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 65 0B 00 00 C7 00 20 20 20 00 EB 06 FF B5 65 0B 00 00 FF B5 61 0B 00 00 FF 95 D6 0A 00 00 85 C0 0F 84 87 00 00 00 89 07 83 C7 04 8B 85 65 0B 00 00 EB 01 40 80 38 00 75 FA 40 89 85 65 0B 00 00 66 81 78 02 00 80 74 A1 80 38 00 75 9C EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 80 3E 01 0F 85 5F FF FF FF 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 69 0B 00 00 FF 95 DE 0A 00 00 68 00 40 00 00 68 00 20 0C 00 FF B5 41 0B 00 00 FF 95 DE 0A 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }
	condition:
		$a0
}

rule RLPack1_20_aPlib0_43___ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack 1.20 (aPlib 0.43) -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 92 05 00 00 EB 0C 8B 85 8E 05 00 00 89 85 92 05 00 00 8D B5 BA 05 00 00 8D 9D 41 04 00 00 33 FF E8 38 01 00 00 EB 1B 8B 85 92 05 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD 9E 05 00 00 00 74 0E 83 BD A2 05 00 00 00 74 05 E8 D6 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 27 05 00 00 89 85 B6 05 00 00 5B FF B5 B6 05 00 00 56 FF D3 83 C4 08 8B B5 B6 05 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 92 05 00 00 83 C0 04 89 85 B2 05 00 00 EB 6E 56 FF 95 1F 05 00 00 0B C0 75 05 E8 C9 02 00 00 85 C0 0F 84 94 00 00 00 89 85 AE 05 00 00 8B C6 EB 2A 8B 85 B2 05 00 00 8B 00 50 FF B5 AE 05 00 00 E8 11 02 00 00 85 C0 74 72 89 07 83 85 B2 05 00 00 04 83 C7 04 8B 85 B2 05 00 00 83 38 00 75 D1 EB 01 46 80 3E 00 75 FA 46 83 C0 04 8B 38 03 BD 92 05 00 00 83 C0 04 89 85 B2 05 00 00 80 3E 01 75 8D 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 B6 05 00 00 FF 95 2B 05 00 00 68 00 80 00 00 6A 00 FF B5 B6 05 00 00 FF 95 2B 05 00 00 E8 61 00 00 00 E8 5C 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }
	condition:
		$a0
}

rule RLPack1_20_LZMA4_30___ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack 1.20 (LZMA 4.30) -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 9C 0C 00 00 EB 0C 8B 85 98 0C 00 00 89 85 9C 0C 00 00 8D B5 C4 0C 00 00 8D 9D 82 04 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 2D 0C 00 00 89 85 94 0C 00 00 E8 59 01 00 00 EB 20 60 8B 85 9C 0C 00 00 FF B5 94 0C 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 C7 08 83 3C 37 00 75 DA 83 BD A8 0C 00 00 00 74 0E 83 BD AC 0C 00 00 00 74 05 E8 F2 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 2D 0C 00 00 89 85 C0 0C 00 00 5B 60 FF B5 94 0C 00 00 56 FF B5 C0 0C 00 00 FF D3 61 8B B5 C0 0C 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 9C 0C 00 00 83 C0 04 89 85 BC 0C 00 00 EB 72 56 FF 95 25 0C 00 00 0B C0 75 05 E8 E6 02 00 00 85 C0 0F 84 AB 00 00 00 89 85 B8 0C 00 00 8B C6 EB 2E 8B 85 BC 0C 00 00 8B 00 50 FF B5 B8 0C 00 00 E8 2E 02 00 00 85 C0 0F 84 85 00 00 00 89 07 83 85 BC 0C 00 00 04 83 C7 04 8B 85 BC 0C 00 00 83 38 00 75 CD EB 01 46 80 3E 00 75 FA 46 83 C0 04 8B 38 03 BD 9C 0C 00 00 83 C0 04 89 85 BC 0C 00 00 80 3E 01 75 89 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 C0 0C 00 00 FF 95 31 0C 00 00 68 00 80 00 00 6A 00 FF B5 C0 0C 00 00 FF 95 31 0C 00 00 68 00 80 00 00 6A 00 FF B5 94 0C 00 00 FF 95 31 0C 00 00 E8 61 00 00 00 E8 5C 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }
	condition:
		$a0
}

rule RLPack1_20Dll_aPlib0_43___ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack 1.20 Dll (aPlib 0.43) -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 6F 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 92 05 00 00 EB 0C 8B 85 8E 05 00 00 89 85 92 05 00 00 8D B5 BA 05 00 00 8D 9D 41 04 00 00 33 FF E8 38 01 00 00 EB 1B 8B 85 92 05 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD 9E 05 00 00 00 74 0E 83 BD A2 05 00 00 00 74 05 E8 D6 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 27 05 00 00 89 85 B6 05 00 00 5B FF B5 B6 05 00 00 56 FF D3 83 C4 08 8B B5 B6 05 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 92 05 00 00 83 C0 04 89 85 B2 05 00 00 EB 6E 56 FF 95 1F 05 00 00 0B C0 75 05 E8 C9 02 00 00 85 C0 0F 84 94 00 00 00 89 85 AE 05 00 00 8B C6 EB 2A 8B 85 B2 05 00 00 8B 00 50 FF B5 AE 05 00 00 E8 11 02 00 00 85 C0 74 72 89 07 83 85 B2 05 00 00 04 83 C7 04 8B 85 B2 05 00 00 83 38 00 75 D1 EB 01 46 80 3E 00 75 FA 46 83 C0 04 8B 38 03 BD 92 05 00 00 83 C0 04 89 85 B2 05 00 00 80 3E 01 75 8D 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 B6 05 00 00 FF 95 2B 05 00 00 68 00 80 00 00 6A 00 FF B5 B6 05 00 00 FF 95 2B 05 00 00 E8 61 00 00 00 E8 5C 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }
	condition:
		$a0
}

rule RLPack1_20Dll_LZMA4_30___ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack 1.20 Dll (LZMA 4.30) -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 AA 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 9C 0C 00 00 EB 0C 8B 85 98 0C 00 00 89 85 9C 0C 00 00 8D B5 C4 0C 00 00 8D 9D 82 04 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 2D 0C 00 00 89 85 94 0C 00 00 E8 59 01 00 00 EB 20 60 8B 85 9C 0C 00 00 FF B5 94 0C 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 C7 08 83 3C 37 00 75 DA 83 BD A8 0C 00 00 00 74 0E 83 BD AC 0C 00 00 00 74 05 E8 F2 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 2D 0C 00 00 89 85 C0 0C 00 00 5B 60 FF B5 94 0C 00 00 56 FF B5 C0 0C 00 00 FF D3 61 8B B5 C0 0C 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 9C 0C 00 00 83 C0 04 89 85 BC 0C 00 00 EB 72 56 FF 95 25 0C 00 00 0B C0 75 05 E8 E6 02 00 00 85 C0 0F 84 AB 00 00 00 89 85 B8 0C 00 00 8B C6 EB 2E 8B 85 BC 0C 00 00 8B 00 50 FF B5 B8 0C 00 00 E8 2E 02 00 00 85 C0 0F 84 85 00 00 00 89 07 83 85 BC 0C 00 00 04 83 C7 04 8B 85 BC 0C 00 00 83 38 00 75 CD EB 01 46 80 3E 00 75 FA 46 83 C0 04 8B 38 03 BD 9C 0C 00 00 83 C0 04 89 85 BC 0C 00 00 80 3E 01 75 89 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 C0 0C 00 00 FF 95 31 0C 00 00 68 00 80 00 00 6A 00 FF B5 C0 0C 00 00 FF 95 31 0C 00 00 68 00 80 00 00 6A 00 FF B5 94 0C 00 00 FF 95 31 0C 00 00 E8 61 00 00 00 E8 5C 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }
	condition:
		$a0
}

rule RLPackFullEdition1_20_aPlib0_43___ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack FullEdition 1.20 (aPlib 0.43) -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 10 00 00 08 00 00 00 }
	condition:
		$a0 at pe.entry_point
}

rule RLPackFullEdition1_20_LZMA4_30___ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack FullEdition 1.20 (LZMA 4.30) -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 10 00 00 08 00 00 00 }
	condition:
		$a0 at pe.entry_point
}

rule RLPackFullEdition1_20_BasicEditionStub___ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack FullEdition 1.20 (BasicEdition Stub) -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 10 00 00 08 00 00 00 }
	condition:
		$a0 at pe.entry_point
}

rule eXPressor_Protection1_5_0_X__CGSoftLabs
{
	meta:
		author = "PEiD"
		description = "eXPressor.Protection 1.5.0.X -> CGSoftLabs"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { EB 01 68 EB 01 ?? ?? ?? ?? 83 EC 0C 53 56 57 EB 01 ?? 83 3D ?? ?? ?? ?? 00 74 08 EB 01 E9 E9 56 01 00 00 EB 02 E8 E9 C7 05 ?? ?? ?? ?? 01 00 00 00 EB 01 C2 E8 E2 05 00 00 EB 02 DA 9F 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF D0 59 59 EB 01 C8 EB 02 66 F0 68 ?? ?? ?? ?? E8 0E 05 00 00 59 EB 01 DD 83 65 F4 00 EB 07 8B 45 F4 40 89 45 F4 83 7D F4 61 73 1F EB 02 DA 1A 8B 45 F4 0F ?? ?? ?? ?? ?? ?? 33 45 F4 8B 4D F4 88 ?? ?? ?? ?? ?? EB 01 EB EB }
	condition:
		$a0 at pe.entry_point
}

rule eXPressor_PacK1_5_0_X__CGSoftLabs
{
	meta:
		author = "PEiD"
		description = "eXPressor.PacK 1.5.0.X -> CGSoftLabs"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 83 A5 ?? ?? ?? ?? ?? F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 35 2E 00 83 7D 0C ?? 75 23 8B 45 08 A3 ?? ?? ?? ?? 6A 04 68 00 10 00 00 68 20 03 00 00 6A 00 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? EB 04 }
	condition:
		$a0
}

rule eXPressor1_4_5_1__CGSoftLabs
{
	meta:
		author = "PEiD"
		description = "eXPressor 1.4.5.1 -> CGSoftLabs"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 EC ?? 53 56 57 83 65 ?? 00 F3 EB 0C ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? A1 ?? ?? ?? ?? 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? B9 ?? ?? ?? ?? 2B 48 18 89 ?? ?? ?? ?? ?? 83 3D ?? ?? ?? ?? ?? 74 16 A1 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 03 48 14 89 4D ?? E9 ?? ?? ?? ?? C7 05 }
	condition:
		$a0
}

rule Themida_WinLicense1_0_0_0_1_8_0_0__OreansTechnologies
{
	meta:
		author = "PEiD"
		description = "Themida/WinLicense 1.0.0.0-1.8.0.0-> Oreans Technologies"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? E8 00 00 00 00 }
	condition:
		$a0
}

rule Themida_WinLicense1_8_0_2___OreansTechnologies
{
	meta:
		author = "PEiD"
		description = "Themida/WinLicense 1.8.0.2 +  -> Oreans Technologies"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { B8 00 00 00 00 60 0B C0 74 68 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 }
	condition:
		$a0
}

rule Themida_WinLicense1_8_X_1_9_X__OreansTechnologies
{
	meta:
		author = "PEiD"
		description = "Themida/WinLicense 1.8.X-1.9.X  -> Oreans Technologies"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D ?? ?? ?? ?? 00 00 58 25 00 F0 FF FF 33 FF 66 BB ?? ?? 66 83 ?? ?? 66 39 18 75 12 0F B7 50 3C 03 D0 BB ?? ?? ?? ?? 83 C3 ?? 39 1A 74 07 2D ?? ?? ?? ?? EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 2D ?? ?? ?? ?? B9 ?? ?? ?? ?? C6 00 E9 83 E9 05 89 48 01 61 E9 }
	condition:
		$a0
}

rule Themida_WinLicense1_0_X_1_7_XDLL__OreansTechnologies
{
	meta:
		author = "PEiD"
		description = "Themida/WinLicense 1.0.X-1.7.X DLL -> Oreans Technologies"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 ?? ?? ?? ?? 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB ?? ?? 66 83 ?? ?? 66 39 18 75 12 0F B7 50 3C 03 D0 BB ?? ?? ?? ?? 83 C3 ?? 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D ?? ?? ?? ?? B9 ?? ?? ?? ?? C6 00 E9 83 E9 ?? 89 48 01 61 E9 }
	condition:
		$a0
}

rule Themida_WinLicense1_XNoCompressionSecureEngine__OreansTechnologies
{
	meta:
		author = "PEiD"
		description = "Themida/WinLicense 1.X NoCompression SecureEngine -> Oreans Technologies"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 89 B5 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 74 0C 8B E8 8B E2 B8 01 00 00 00 C2 0C 00 8B 44 24 24 89 85 ?? ?? ?? ?? 6A 45 E8 A3 00 00 00 68 9A 74 83 07 E8 DF 00 00 00 68 25 4B 89 0A E8 D5 00 00 00 E9 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$a0 at pe.entry_point
}

rule Themida_WinLicense1_X__OreansTechnologies
{
	meta:
		author = "PEiD"
		description = "Themida/WinLicense 1.X -> Oreans Technologies"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 43 4F 4D 43 54 4C 33 32 2E 64 6C 6C 00 00 00 49 6E 69 74 43 6F 6D 6D 6F 6E 43 6F 6E 74 72 6F 6C 73 00 00 00 00 00 00 }
	condition:
		$a0 at pe.entry_point
}

rule ThinstallVirtualizationSuite3_035_3_043__ThinstallCompany
{
	meta:
		author = "PEiD"
		description = "Thinstall Virtualization Suite 3.035-3.043 -> Thinstall Company"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 28 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB }
	condition:
		$a0
}

rule ThinstallVirtualizationSuite3_049_3_080__ThinstallCompany
{
	meta:
		author = "PEiD"
		description = "Thinstall Virtualization Suite 3.049-3.080 -> Thinstall Company"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 2C 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB }
	condition:
		$a0
}

rule ThinstallVirtualizationSuite3_0X__ThinstallCompany
{
	meta:
		author = "PEiD"
		description = "Thinstall Virtualization Suite 3.0X -> Thinstall Company"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 9C 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 BA FE FF FF E9 ?? ?? ?? ?? CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA ?? ?? ?? ?? 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 ?? ?? ?? ?? E8 DF 00 00 00 73 1B 55 BD ?? ?? ?? ?? E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB }
	condition:
		$a0
}

rule ThinstallVirtualizationSuite3_0x_3_300__ThinstallInc_
{
	meta:
		author = "PEiD"
		description = "Thinstall Virtualization Suite 3.0x - 3.300 -> Thinstall Inc."
		group = "Auto"
		function = "0"
	strings:
		$a0 = { CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 ?? ?? ?? 33 DB BA ?? ?? ?? ?? 43 33 C0 E8 19 01 ?? ?? 73 0E 8B 4D F8 E8 27 01 ?? ?? 02 45 F7 AA EB E9 E8 04 01 ?? ?? 0F 82 96 ?? ?? ?? E8 F9 ?? ?? ?? 73 5B B9 04 ?? ?? ?? E8 05 01 ?? ?? 48 74 DE 0F 89 ?? ?? ?? ?? E8 DF ?? ?? ?? 73 1B 55 BD ?? ?? ?? ?? E8 DF ?? ?? ?? 88 07 47 4D 75 F5 E8 C7 ?? ?? ?? 72 E9 5D }
	condition:
		$a0 at pe.entry_point
}

rule ThinstallVirtualizationSuite3_0x_3_330__ThinstallInc_
{
	meta:
		author = "PEiD"
		description = "Thinstall Virtualization Suite 3.0x - 3.330 -> Thinstall Inc."
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? FF FF E9 90 FF FF FF CC CC }
	condition:
		$a0
}

rule Armadillo3_X_5_X__SiliconRealmsToolworks
{
	meta:
		author = "PEiD"
		description = "Armadillo 3.X-5.X -> Silicon Realms Toolworks"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 60 33 C9 75 02 EB 15 EB 33 }
	condition:
		$a0
}

rule Armadillo5_0X__SiliconRealmsToolworks
{
	meta:
		author = "PEiD"
		description = "Armadillo 5.0X -> Silicon Realms Toolworks"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { E8 E3 40 00 00 E9 16 FE FF FF 6A 0C 68 ?? ?? ?? ?? E8 44 15 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 36 13 00 00 C7 00 0C 00 00 00 57 57 57 57 57 E8 C7 12 00 00 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D ?? ?? ?? ?? 03 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 ?? ?? ?? ?? 77 37 6A 04 E8 48 11 00 00 59 89 7D FC ?? 75 08 E8 01 49 00 00 59 89 45 E4 C7 45 FC FE FF FF FF E8 5F 00 00 00 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 66 D3 FF FF 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 3B DF 75 4C 39 3D ?? ?? ?? ?? 74 33 56 E8 AF F9 FF FF 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 EE 0F 00 00 59 C3 }
	condition:
		$a0
}

rule Armadillo5_0XDll__SiliconRealmsToolworks
{
	meta:
		author = "PEiD"
		description = "Armadillo 5.0X Dll -> Silicon Realms Toolworks"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 83 7C 24 08 01 75 05 E8 ?? ?? ?? ?? FF 74 24 04 8B 4C 24 10 8B 54 24 0C E8 ?? ?? ?? ?? 59 C2 0C 00 6A 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 ?? ?? ?? ?? C7 00 0C 00 00 00 57 57 57 57 57 E8 ?? ?? ?? ?? 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D ?? ?? ?? ?? 03 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 ?? ?? ?? ?? 77 37 6A 04 E8 ?? ?? ?? ?? 59 89 7D FC FF 75 08 E8 ?? ?? ?? ?? 59 89 45 E4 C7 45 FC FE FF FF FF E8 ?? ?? ?? ?? 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 ?? ?? ?? ?? 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 3B DF 75 4C 39 3D ?? ?? ?? ?? 74 33 56 E8 ?? ?? ?? ?? 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 ?? ?? ?? ?? 59 C3 }
	condition:
		$a0
}

rule NTkrnlSecureSuite0_1_0_15__NTkrnlSoftware
{
	meta:
		author = "PEiD"
		description = "NTkrnl Secure Suite 0.1-0.15 -> NTkrnl Software"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 }
	condition:
		$a0 at pe.entry_point
}

rule NTkrnlSecureSuite0_1_0_15DLL__NTkrnlSoftware
{
	meta:
		author = "PEiD"
		description = "NTkrnl Secure Suite 0.1-0.15 DLL -> NTkrnl Software"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 8B 44 24 04 05 ?? ?? ?? ?? 50 E8 01 00 00 00 C3 C3 }
	condition:
		$a0 at pe.entry_point
}

rule NTkrnlSecureSuite__NTkrnlteam
{
	meta:
		author = "PEiD"
		description = "NTkrnl Secure Suite -> NTkrnl team"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 10 00 00 50 10 00 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 }
	condition:
		$a0 at pe.entry_point
}

rule NTkrnlSecureSuite__NTkrnlTeam_Blue_
{
	meta:
		author = "PEiD"
		description = "NTkrnl Secure Suite -> NTkrnl Team (Blue)"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 68 29 19 43 00 E8 01 00 00 00 C3 C3 A2 A9 61 4E A5 0E C7 A6 59 90 6E 4D 4C DB 36 46 FB 6E C4 45 A3 C2 2E 0E 41 59 1A 50 17 39 62 4D B8 61 24 8E CF D1 0E 9E 7A 66 C0 8D 6B 9C 52 7E 96 46 80 AF }
	condition:
		$a0 at pe.entry_point
}

rule MicroJoiner1_7Private__GlOFF
{
	meta:
		author = "PEiD"
		description = "MicroJoiner 1.7 Private -> GlOFF"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 90 BF F7 FF FF FF 87 D2 90 BF F7 FF FF FF BF 2F 10 40 00 87 D2 90 87 D2 8D 5F 21 87 D2 6A 0A 87 D2 58 6A 04 87 D2 59 60 87 D2 57 87 D2 E8 AC 00 00 00 90 95 8B 55 3C 87 D2 8B 74 2A 78 87 D2 8D 74 2E 18 AD 87 D2 91 87 D2 AD 50 87 D2 AD 03 C5 87 D2 92 87 D2 AD 03 C5 50 87 D2 8B F2 AD 03 C5 33 D2 87 D2 C1 C2 03 87 D2 32 10 40 87 D2 80 38 00 75 EF 8B 04 24 87 D2 83 04 24 02 8B FB 87 D2 }
	condition:
		$a0
}

rule VPacker0_02_10build060420__tt_t
{
	meta:
		author = "PEiD"
		description = "VPacker 0.02.10 build 060420 -> tt.t"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 36 FE FF FF C3 90 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? 00 00 ?? ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? ?? 00 00 ?? ?? ?? 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? 00 }
	condition:
		$a0
}

rule VPacker0_02_10build060420__tt_t_
{
	meta:
		author = "PEiD"
		description = "VPacker 0.02.10 build 060420 -> tt.t"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 C4 D4 53 56 57 8B 45 10 83 C0 0C 8B 00 89 45 DC 83 7D DC 00 75 08 E8 AD FF FF FF 89 45 DC E8 B9 FE FF FF 8B 10 03 55 DC 89 55 E4 83 C0 04 8B 10 89 55 FC 83 C0 04 8B 10 89 55 F4 83 C0 04 8B 10 89 55 F8 83 C0 04 8B 10 89 55 F0 83 C0 04 8B 10 89 55 EC 83 C0 04 8B 00 89 45 E8 8B 45 E4 8B 58 04 03 5D E4 8B FB 8B 45 E4 8B 30 4E 85 F6 72 2B 46 C7 45 E0 00 00 00 00 83 7B 04 00 74 14 8B 03 03 C7 8B 53 08 03 55 DC 52 50 E8 89 FE FF FF }
	condition:
		$a0 at pe.entry_point
}

rule PE_DIYTools1_10__W_YongStudio
{
	meta:
		author = "PEiD"
		description = "PE-DIY Tools 1.10 -> W-Yong Studio"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { E8 00 00 00 00 5D 81 ED ?? ?? 40 00 8B 85 ?? ?? 40 00 FF 10 8B 85 ?? ?? 40 00 FF E0 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 }
	condition:
		$a0
}

rule SimpleVBPECrypter__dzzie
{
	meta:
		author = "PEiD"
		description = "Simple VB PE Crypter -> dzzie"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { C7 45 F4 00 00 40 00 C7 45 F0 ?? ?? ?? ?? 8B 45 F4 05 ?? ?? 00 00 89 45 F4 C7 45 FC 00 00 00 00 EB 09 8B 4D FC 83 C1 01 89 4D FC 8B 55 FC 3B 55 F0 7D 22 8B 45 F4 03 45 FC 8A 08 88 4D F8 0F BE 55 F8 83 F2 0F 88 55 F8 8B 45 F4 03 45 FC 8A 4D F8 88 08 EB CD FF 65 F4 }
	condition:
		$a0
}

rule XComp0_97_0_98__JoKo
{
	meta:
		author = "PEiD"
		description = "XComp 0.97/0.98 -> JoKo"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 68 ?? ?? ?? ?? 9C 60 E8 ?? ?? 00 00 34 ?? ?? 00 00 00 00 00 00 00 00 00 4C ?? ?? 00 34 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 59 ?? ?? 00 6A ?? ?? 00 79 ?? ?? 00 88 ?? ?? 00 96 ?? ?? 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 }
	condition:
		$a0
}

rule XPack0_97_0_98__JoKo
{
	meta:
		author = "PEiD"
		description = "XPack 0.97/0.98 -> JoKo"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 68 ?? ?? ?? ?? 9C 60 E8 ?? ?? 00 00 34 ?? ?? 00 00 00 00 00 00 00 00 00 44 ?? ?? 00 34 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 51 ?? ?? 00 62 ?? ?? 00 71 ?? ?? 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 }
	condition:
		$a0
}

rule CodeVeil1_2R5465__XheoInc_
{
	meta:
		author = "PEiD"
		description = "CodeVeil 1.2 R5465 -> Xheo Inc."
		group = "Auto"
		function = "0"
	strings:
		$a0 = { E9 29 01 00 00 8D 49 00 44 25 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 43 56 31 30 2D 35 44 56 47 42 36 45 2D 32 4A 36 58 49 2D 32 48 4E 35 4A 2D 32 55 58 32 31 2D 47 55 57 48 42 }
	condition:
		$a0 at pe.entry_point
}

rule CodeVeil1_2R5465DLL__XheoInc_
{
	meta:
		author = "PEiD"
		description = "CodeVeil 1.2 R5465 DLL -> Xheo Inc."
		group = "Auto"
		function = "0"
	strings:
		$a0 = { E9 29 01 00 00 8D 49 00 64 19 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 43 56 31 30 2D 35 44 56 47 42 36 45 2D 32 4A 36 58 49 2D 32 48 4E 35 4A 2D 32 55 58 32 31 2D 47 55 57 48 42 }
	condition:
		$a0 at pe.entry_point
}

rule CodeVeil1_2_x_1_3_x__XheoInc_
{
	meta:
		author = "PEiD"
		description = "CodeVeil 1.2.x/1.3.x -> Xheo Inc."
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 8B FF 60 E8 01 00 00 00 B8 5E E8 01 00 00 00 B8 58 2D 31 01 00 00 8B 00 2B F0 81 E6 00 00 FF FF 03 76 3C 33 C9 66 8B 4E 14 8D 74 31 18 8B 5E 0C 03 DE 81 E3 00 F0 FF FF 8B 56 08 E8 05 00 00 00 E9 93 00 00 00 55 8B EC 83 C4 F0 B9 E9 00 00 00 8B F3 03 DA E8 01 00 00 00 B8 58 2D 77 01 00 00 8B 00 03 C6 89 45 F4 E8 01 00 00 00 B8 5A 81 EA 86 01 00 00 8B 12 03 D0 89 55 F0 E8 01 00 00 00 B8 5A 81 EA A6 01 00 00 8B 12 E8 01 00 00 00 E9 5F 81 C7 A3 00 00 00 03 D7 }
	condition:
		$a0 at pe.entry_point
}

rule iPBProtect0_1_5Beta__FORGAT_iPB
{
	meta:
		author = "PEiD"
		description = "iPBProtect 0.1.5 Beta -> FORGAT/iPB"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 55 8B EC 6A FF 68 4B 43 55 46 68 54 49 48 53 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 68 53 56 57 89 65 FA 33 DB 89 5D F8 6A 02 EB 01 F8 58 5F 5E 5B 64 8B 25 00 00 00 00 64 8F 05 00 00 00 00 58 58 58 5D 68 9F 6F 56 B6 50 E8 5D 00 00 00 EB FF 71 78 C2 50 00 EB D3 5B F3 68 89 5C 24 48 5C 24 58 FF 8D 5C 24 58 5B 83 C3 4C 75 F4 5A 8D 71 78 75 09 81 F3 EB FF 52 BA 01 00 83 EB FC 4A FF 71 0F 75 19 8B 5C 24 00 00 81 33 50 53 8B 1B 0F FF C6 75 1B 81 F3 EB 87 1C 24 8B 8B 04 24 83 EC FC EB 01 E8 83 EC FC E9 E7 00 00 00 58 EB FF F0 EB FF C0 83 E8 FD EB FF 30 E8 C9 00 00 00 89 E0 EB FF D0 EB FF 71 0F 83 C0 01 EB FF 70 F0 71 EE EB FA EB 83 C0 14 EB FF 70 ED 71 EB EB FA FF 83 C0 FC EB FF 70 ED 71 EB EB FA 0F 83 C0 F8 EB FF 70 ED 71 EB EB FA FF 83 C0 18 EB FF 70 ED 71 EB EB FA 78 83 C0 04 EB FF 70 ED 71 EB EB FA 71 83 C0 08 EB FF 70 ED 71 EB EB FA 71 83 C0 0C EB FF 70 ED 71 EB EB FA EB 83 C0 F8 EB FF 70 ED 71 EB EB FA FF 83 C0 EC EB FF 70 ED 71 EB EB FA EB 83 C0 F0 EB FF 70 ED 71 EB EB FA 71 83 C0 F8 EB FF 70 ED 71 EB EB FA 71 83 C0 14 EB FF 70 ED 71 EB EB FA EB 83 C0 10 EB FF 70 ED 71 EB EB FA 78 83 C0 0C EB FF 70 ED 71 EB EB FA FF 83 C0 08 EB FF 70 ED 71 EB EB FA EB 83 C0 17 EB FF 70 ED 71 EB EB FA EB }
	condition:
		$a0
}

rule iPBProtect0_1_5Beta__FORGAT_iPB_
{
	meta:
		author = "PEiD"
		description = "iPBProtect 0.1.5 Beta -> FORGAT/iPB"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 48 4D 4D 4D 2C 20 49 20 57 49 4C 4C 20 53 57 49 54 43 48 20 54 4F 20 48 41 52 44 43 4F 52 45 20 4D 4F 44 45 21 21 21 4D 55 48 41 48 41 48 41 00 00 00 00 00 00 00 00 00 00 00 00 57 ?? ?? 00 64 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 45 72 4E 65 4C 33 32 2E 64 4C 6C 00 6C ?? ?? 00 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 }
	condition:
		$a0 at pe.entry_point
}

rule ZXCriptor__da_ff_VaV
{
	meta:
		author = "PEiD"
		description = "ZXCriptor -> da_ff & VaV"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 64 FF 30 64 89 20 8D 55 FC B8 E4 1C 44 44 E8 EE FE FF FF 8B 45 FC E8 92 FB FF FF 50 E8 BC FF FF FF 8B D8 8D 55 F8 B8 FC 1C 44 44 E8 D1 FE FF FF 8B 45 F8 E8 75 FB FF FF 50 53 E8 A6 FF FF FF A3 34 ?? ?? 44 8D 55 F4 B8 14 1D 44 44 E8 B0 FE FF FF 8B 45 F4 E8 54 FB FF FF 50 53 E8 85 FF FF FF A3 38 ?? ?? 44 8D 55 F0 B8 30 1D 44 44 E8 8F FE FF FF 8B 45 F0 E8 33 FB FF FF 50 53 E8 64 FF FF FF A3 2C ?? ?? 44 8D 55 EC B8 48 1D 44 44 E8 6E FE FF FF 8B 45 EC E8 12 FB FF FF 50 53 E8 43 FF FF FF A3 30 ?? ?? 44 33 C0 5A 59 59 64 89 10 68 D4 1C 44 44 8D 45 EC BA 05 00 00 00 E8 B0 F9 FF FF C3 E9 56 F7 FF FF EB EB 5B 8B E5 5D C3 00 00 00 FF FF FF FF 0C 00 00 00 E2 EF F9 E2 E8 E2 BC A2 BF F6 FF F8 00 00 00 00 FF FF FF FF 0E 00 00 00 DF E3 F9 F8 F8 EF E3 D1 FD FE FC F7 D0 EE 00 00 FF FF FF FF 11 00 00 00 DB EF EA E8 DD FC E0 F3 F4 E1 E0 D9 F0 FB F8 EA E0 00 00 00 FF FF FF FF 0E 00 00 00 CA F8 EE ED F9 EB DF E2 FE F1 F6 E7 E6 D7 00 00 FF FF FF FF 12 00 00 00 DE F8 E2 F8 E8 DE FD FF F2 F7 E0 E7 D8 F3 FA F7 EB E3 00 00 55 8B EC 81 C4 C0 FE FF FF 53 56 57 33 D2 89 95 C0 FE FF FF 89 45 FC 33 C0 55 68 ?? ?? 44 44 64 FF 30 64 89 20 }
	condition:
		$a0 at pe.entry_point
}

rule Exe86_Fake1_0__exe86_com
{
	meta:
		author = "PEiD"
		description = "Exe86_Fake 1.0 -> exe86.com"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { A0 E5 14 00 00 00 00 00 00 00 00 00 00 00 00 00 60 E7 14 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 30 E5 14 00 00 00 00 00 26 F6 05 66 00 00 00 00 10 E6 14 00 00 00 00 00 00 00 00 00 00 00 00 00 F0 E6 14 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 40 E9 14 00 88 A8 01 66 02 00 00 00 00 00 00 00 90 67 40 00 2A 00 5C 00 41 00 43 00 3A 00 5C 00 44 00 6F 00 63 00 75 00 6D 00 65 00 6E 00 74 00 73 00 20 00 61 00 6E 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 6E 00 67 00 73 00 5C 00 41 00 64 00 6D 00 69 00 6E 00 69 00 73 00 74 00 72 00 61 00 74 00 6F 00 72 00 5C 00 4C 68 62 97 5C 00 6A 00 75 00 6E 00 6B 00 43 00 6F 00 64 00 65 00 5F 00 6B 00 79 00 6C 00 69 00 6E 00 5F 00 76 00 31 00 5B 00 31 00 5D 00 2E 00 30 00 5C 00 E5 5D 0B 7A 31 00 2E 00 76 00 62 00 70 00 }
	condition:
		$a0 at pe.entry_point
}

rule XpFoxVC____XpFox
{
	meta:
		author = "PEiD"
		description = "XpFox VC++ -> XpFox"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 55 8B EC 6A FF 68 2A 2C 0A 00 68 38 90 0D 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 B8 ?? ?? ?? ?? FF E0 90 00 00 00 00 00 00 00 00 00 00 00 00 00 00 9C 6C 40 00 BC 6B 40 00 7C 09 41 00 04 6C 40 00 04 6B 40 00 EC 6C 40 00 2C 6D 40 00 94 6D 40 00 50 AD 41 00 34 C0 48 00 BC 6C 40 00 D8 AD 41 00 F0 AD 41 00 A8 AC 41 00 28 C0 48 00 98 E2 45 00 3C 6C 40 00 A8 E2 45 00 28 AD 41 00 10 90 48 00 A4 6D 40 00 44 C0 48 00 08 C0 48 00 DC 6A 40 00 70 AC 41 00 4C C9 48 00 D0 AD 41 00 7C 6D 40 00 C0 AD 41 00 A4 6C 40 00 20 AC 41 00 18 AE 41 00 F8 AD 41 00 E0 AD 41 00 34 6C 40 00 14 6C 40 00 00 AD 41 00 C8 AB 41 00 A0 AC 41 00 EC C7 48 00 E0 AC 41 00 D8 AC 41 00 D0 AC 41 00 1C 6B 40 00 08 AC 41 00 C4 6A 40 00 58 AC 41 }
	condition:
		$a0
}

rule UPX2_00_3_0X__MarkusOberhumer_LaszloMolnar_JohnReiser
{
	meta:
		author = "PEiD"
		description = "UPX 2.00-3.0X -> Markus Oberhumer & Laszlo Molnar & John Reiser"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 5E 89 F7 B9 ?? ?? ?? ?? 8A 07 47 2C E8 3C 01 77 F7 80 3F ?? 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 29 F8 80 EB E8 01 F0 89 07 83 C7 05 88 D8 E2 D9 8D ?? ?? ?? ?? ?? 8B 07 09 C0 74 3C 8B 5F 04 8D ?? ?? ?? ?? ?? ?? 01 F3 50 83 C7 08 FF ?? ?? ?? ?? ?? 95 8A 07 47 08 C0 74 DC 89 F9 57 48 F2 AE 55 FF ?? ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB E1 FF ?? ?? ?? ?? ?? 8B AE ?? ?? ?? ?? 8D BE 00 F0 FF FF BB 00 10 00 00 50 54 6A 04 53 57 FF D5 8D 87 ?? ?? ?? ?? 80 20 7F 80 60 28 7F 58 50 54 50 53 57 FF D5 58 61 8D 44 24 80 6A 00 39 C4 75 FA 83 EC 80 E9 }
	condition:
		$a0 at pe.entry_point
}

rule ARMProtector0_3_bySMoKE
{
	meta:
		author = "PEiD"
		description = "ARM Protector 0.3 - by SMoKE"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 13 24 40 00 EB 02 83 09 8D B5 A4 24 40 00 EB 02 83 09 BA 4B 15 00 00 EB 01 00 8D 8D EF 39 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 50 C3 8A 06 46 EB 01 00 D0 C8 E8 14 00 00 00 83 EB 01 00 2A C2 E8 00 00 00 00 5B 83 C3 07 53 C3 00 EB 04 5B 43 53 C3 EB 01 00 32 C2 E8 0B 00 00 00 00 32 C1 EB 01 00 C0 C0 02 EB 09 2A C2 5B EB 01 00 43 53 C3 88 07 EB 01 00 47 4A 75 B4 }
	condition:
		$a0
}

rule AntiDote1_0Beta__SIS_Team
{
	meta:
		author = "PEiD"
		description = "AntiDote 1.0 Beta -> SIS-Team"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { E8 BB FF FF FF 84 C0 74 2F 68 04 01 00 00 68 C0 23 60 00 6A 00 FF 15 08 10 60 00 E8 40 FF FF FF 50 68 78 11 60 00 68 68 11 60 00 68 C0 23 60 00 E8 AB FD FF FF 83 C4 10 33 C0 C2 10 00 90 90 90 8B 4C 24 08 56 8B 74 24 08 33 D2 8B C6 F7 F1 8B C6 85 D2 74 08 33 D2 F7 F1 40 0F AF C1 5E C3 90 8B 44 24 04 53 55 56 8B 48 3C 57 03 C8 33 D2 8B 79 54 8B 71 38 8B C7 F7 F6 85 D2 74 0C 8B C7 33 D2 F7 F6 8B F8 47 0F AF FE 33 C0 33 DB 66 8B 41 14 8D 54 08 18 33 C0 66 8B 41 06 89 54 24 14 8D 68 FF 85 ED 7C 37 33 C0 }
	condition:
		$a0
}

rule AntiDote1_0Demo_1_2__SIS_Team
{
	meta:
		author = "PEiD"
		description = "AntiDote 1.0 Demo / 1.2 -> SIS-Team"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 00 00 00 00 09 01 47 65 74 43 6F 6D 6D 61 6E 64 4C 69 6E 65 41 00 DB 01 47 65 74 56 65 72 73 69 6F 6E 45 78 41 00 73 01 47 65 74 4D 6F 64 75 6C 65 46 69 6C 65 4E 61 6D 65 41 00 00 7A 03 57 61 69 74 46 6F 72 53 69 6E 67 6C 65 4F 62 6A 65 63 74 00 BF 02 52 65 73 75 6D 65 54 68 72 65 61 64 00 00 29 03 53 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74 00 00 94 03 57 72 69 74 65 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79 00 00 6B 03 56 69 72 74 75 61 6C 41 6C 6C 6F 63 45 78 00 00 A6 02 52 65 61 64 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79 00 CA 01 47 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74 00 00 62 00 43 72 65 61 74 65 50 72 6F 63 65 73 73 41 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C }
	condition:
		$a0 at pe.entry_point
}

rule AntiDote1_2Beta_Demo___SIS_Team
{
	meta:
		author = "PEiD"
		description = "AntiDote 1.2 Beta (Demo) -> SIS-Team"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 68 69 D6 00 00 E8 C6 FD FF FF 68 69 D6 00 00 E8 BC FD FF FF 83 C4 08 E8 A4 FF FF FF 84 C0 74 2F 68 04 01 00 00 68 B0 21 60 00 6A 00 FF 15 08 10 60 00 E8 29 FF FF FF 50 68 88 10 60 00 68 78 10 60 00 68 B0 21 60 00 E8 A4 FD FF FF 83 C4 10 33 C0 C2 10 00 90 90 90 90 90 90 90 90 90 90 90 90 8B 4C 24 08 56 8B 74 24 08 33 D2 8B C6 F7 F1 8B C6 85 D2 74 08 33 D2 F7 F1 40 0F AF C1 5E C3 90 8B 44 24 04 53 55 56 8B 48 3C 57 03 C8 33 D2 8B 79 54 8B 71 38 8B C7 F7 F6 85 D2 74 0C 8B C7 33 D2 F7 F6 8B F8 47 0F AF FE 33 C0 33 DB 66 8B 41 14 8D 54 08 18 33 C0 }
	condition:
		$a0
}

rule AntiDote1_2_Demo__SIS_Team
{
	meta:
		author = "PEiD"
		description = "AntiDote 1.2.Demo -> SIS-Team"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { E8 F7 FE FF FF 05 CB 22 00 00 FF E0 E8 EB FE FF FF 05 BB 19 00 00 FF E0 E8 BD 00 00 00 08 B2 62 00 01 52 17 0C 0F 2C 2B 20 7F 52 79 01 30 07 17 29 4F 01 3C 30 2B 5A 3D C7 26 11 26 06 59 0E 78 2E 10 14 0B 13 1A 1A 3F 64 1D 71 33 57 21 09 24 8B 1B 09 37 08 61 0F 1D 1D 2A 01 87 35 4C 07 39 0B }
	condition:
		$a0 at pe.entry_point
}

rule AntiDote1_4SE__SIS_Team
{
	meta:
		author = "PEiD"
		description = "AntiDote 1.4 SE -> SIS-Team"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 68 90 03 00 00 E8 C6 FD FF FF 68 90 03 00 00 E8 BC FD FF FF 68 90 03 00 00 E8 B2 FD FF FF 50 E8 AC FD FF FF 50 E8 A6 FD FF FF 68 69 D6 00 00 E8 9C FD FF FF 50 E8 96 FD FF FF 50 E8 90 FD FF FF 83 C4 20 E8 78 FF FF FF 84 C0 74 4F 68 04 01 00 00 68 10 22 60 00 6A 00 FF 15 08 10 60 00 68 90 03 00 00 E8 68 FD FF FF 68 69 D6 00 00 E8 5E FD FF FF 50 E8 58 FD FF FF 50 E8 52 FD FF FF E8 DD FE FF FF 50 68 A4 10 60 00 68 94 10 60 00 68 10 22 60 00 E8 58 FD FF FF 83 C4 20 33 C0 C2 10 00 8B 4C 24 08 56 8B 74 24 08 33 D2 8B C6 F7 F1 8B C6 85 D2 74 08 33 D2 F7 F1 40 0F AF C1 5E C3 }
	condition:
		$a0
}

rule BlindSpot1_0__s134k
{
	meta:
		author = "PEiD"
		description = "BlindSpot 1.0 -> s134k"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 55 8B EC 81 EC 50 02 00 00 8D 85 B0 FE FF FF 53 56 A3 90 12 40 00 57 8D 85 B0 FD FF FF 68 00 01 00 00 33 F6 50 56 FF 15 24 10 40 00 56 68 80 00 00 00 6A 03 56 56 8D 85 B0 FD FF FF 68 00 00 00 80 50 FF 15 20 10 40 00 56 56 68 00 08 00 00 50 89 45 FC FF 15 1C 10 40 00 8D 45 F8 8B 1D 18 10 40 00 56 50 6A 34 FF 35 90 12 40 00 FF 75 FC FF D3 85 C0 0F 84 7F 01 00 00 39 75 F8 0F 84 76 01 00 00 A1 90 12 40 00 66 8B 40 30 66 3D 01 00 75 14 8D 85 E4 FE FF FF 68 04 01 00 00 50 FF 15 14 10 40 00 EB 2C 66 3D 02 00 75 14 8D 85 E4 FE FF FF 50 68 04 01 00 00 FF 15 10 10 40 00 EB 12 8D 85 E4 FE FF FF 68 04 01 00 00 50 FF 15 0C 10 40 00 8B 3D 08 10 40 00 8D 85 E4 FE FF FF 68 54 10 40 00 50 }
	condition:
		$a0 at pe.entry_point
}

rule Upack0_29Beta_0_31Beta__Dwing
{
	meta:
		author = "PEiD"
		description = "Upack 0.29 Beta - 0.31 Beta -> Dwing"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { BE 88 01 ?? ?? AD 8B F8 95 AD 91 F3 A5 AD B5 ?? F3 }
	condition:
		$a0 at pe.entry_point
}

rule AverCryptor1_02beta__os1r1s
{
	meta:
		author = "PEiD"
		description = "AverCryptor 1.02 beta -> os1r1s"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 0C 17 40 00 8B BD 33 18 40 00 8B 8D 3B 18 40 00 B8 51 18 40 00 03 C5 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 37 18 40 00 33 C0 51 33 C9 66 B9 F7 00 66 83 F9 00 74 49 8B 57 0C 03 95 37 18 40 00 8B 85 3F 18 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 8B F1 E8 27 00 00 00 8B C8 5F B8 51 18 40 00 03 C5 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 2F 18 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 23 F7 8B C6 5F 5E C3 }
	condition:
		$a0
}

rule AverCryptor1_0__os1r1s
{
	meta:
		author = "PEiD"
		description = "AverCryptor 1.0 -> os1r1s"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 75 17 40 00 8B BD 9C 18 40 00 8B 8D A4 18 40 00 B8 BC 18 40 00 03 C5 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 A0 18 40 00 33 C0 51 33 C9 66 B9 FA 00 66 83 F9 00 74 49 8B 57 0C 03 95 A0 18 40 00 8B 85 A8 18 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 8B F1 E8 27 00 00 00 8B C8 5F B8 BC 18 40 00 03 C5 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 98 18 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 23 F7 8B C6 5F 5E C3 }
	condition:
		$a0
}

rule D1S1G1_1Beta__ScrambledEXE__D1N
{
	meta:
		author = "PEiD"
		description = "D1S1G 1.1 Beta ++ Scrambled EXE -> D1N"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { E8 07 00 00 00 E8 1E 00 00 00 C3 90 58 89 C2 89 C2 25 00 F0 FF FF 50 83 C0 55 8D 00 FF 30 8D 40 04 FF 30 52 C3 8D 40 00 55 8B EC 83 C4 E8 53 56 57 8B 4D 10 8B 45 08 89 45 F8 8B 45 0C 89 45 F4 8D 41 61 8B 38 8D 41 65 8B 00 03 C7 89 45 FC 8D 41 69 8B 00 03 C7 8D 51 6D 8B 12 03 D7 83 C1 71 8B 09 03 CF 2B CA 72 0A 41 87 D1 80 31 FF 41 4A 75 F9 89 45 F0 EB 71 8B }
	condition:
		$a0 at pe.entry_point
}

rule Crypter3_1__SLESH
{
	meta:
		author = "PEiD"
		description = "Crypter 3.1 -> SLESH"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 68 FF 64 24 F0 68 58 58 58 58 FF D4 50 8B 40 F2 05 B0 95 F6 95 0F 85 01 81 BB FF 68 }
	condition:
		$a0 at pe.entry_point
}

rule COOLcryptor0_2__kongfoo
{
	meta:
		author = "PEiD"
		description = "COOLcryptor 0.2 -> kongfoo"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED A5 1F 40 00 B9 D4 0C 00 00 8D BD ED 1F 40 00 8B F7 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC }
	condition:
		$a0
}

rule COOLcryptor0_9__kongfoo
{
	meta:
		author = "PEiD"
		description = "COOLcryptor 0.9 -> kongfoo"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { E8 03 00 00 00 E9 EB 07 FF 04 24 EB 01 FF C3 E8 03 00 00 00 EB 02 EA C3 EB 08 8D 8D 72 08 73 06 9A E8 70 F8 71 F6 E8 02 00 00 00 C7 05 83 C4 04 EB 05 E8 FE 04 24 C3 E8 F7 FF FF FF E9 EB 02 E9 01 EB 03 C7 84 39 66 9C 6A 0E EB 0B EB 02 C1 51 FF 0C 24 EB 05 CA 11 EB F7 CD EB 02 99 EB 75 EA 74 01 75 66 9D 70 03 71 01 FF 83 C4 04 EB 01 75 66 9C 72 0C 73 0A EB 01 63 E8 07 00 00 00 EB 0F 72 F4 73 F2 83 83 C4 04 66 9D EB 01 75 EB 1D 8A E8 01 00 00 00 83 58 EB 04 E9 EB 05 E8 EB FB C7 85 83 C0 19 EB 02 FF 15 FF E0 FF 25 EB E2 E8 03 00 00 00 E9 EB 07 FF 04 24 EB 01 FF C3 }
	condition:
		$a0
}

rule DotFixNiceProtect2_1__GPcHSoft
{
	meta:
		author = "PEiD"
		description = "DotFix Nice Protect 2.1 - 2.5 -> GPcH Soft"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { E9 FF 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 2B 7C 24 28 89 7C 24 1C 61 C3 60 B8 ?? ?? ?? ?? 03 C5 50 B8 ?? ?? ?? ?? 03 C5 FF 10 BB ?? ?? ?? ?? 03 DD 83 C3 0C 53 50 B8 ?? ?? ?? ?? 03 C5 FF 10 6A 40 68 00 10 00 00 FF 74 24 2C 6A 00 FF D0 89 44 24 1C 61 C3 }
	condition:
		$a0 at pe.entry_point
}

rule DEF1_0
{
	meta:
		author = "PEiD"
		description = "DEF 1.0"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { BE ?? 01 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 ?? ?? 40 00 C3 }
	condition:
		$a0 at pe.entry_point
}

rule Upx_Lock1_0_1_2__CyberDoom_Team_X_BoB_TeamPEiD
{
	meta:
		author = "PEiD"
		description = "Upx-Lock 1.0 - 1.2 -> CyberDoom / Team-X + BoB / Team PEiD"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 48 12 40 00 60 E8 2B 03 00 00 61 }
	condition:
		$a0
}

rule Packman1_0__BrandonLaCombe
{
	meta:
		author = "PEiD"
		description = "Packman 1.0 -> Brandon LaCombe"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B C6 01 1B 8B 13 8D 73 14 6A 08 59 01 16 AD 49 75 FA 8B E8 C6 06 E9 8B 43 0C 89 46 01 6A 04 68 00 10 00 00 FF 73 08 51 FF 55 08 8B }
	condition:
		$a0
}

rule QuickPack01
{
	meta:
		author = "PEiD"
		description = "QuickPack NT 0.1 -> ?"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 62 01 00 00 50 45 00 00 4C 01 01 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 00 40 00 00 10 00 }
	condition:
		$a0
}

rule RCryptor1_1__Vaska
{
	meta:
		author = "PEiD"
		description = "RCryptor 1.1 -> Vaska"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 8B 04 24 83 E8 4F 68 ?? ?? ?? ?? FF D0 }
	condition:
		$a0 at pe.entry_point
}

rule RCryptor1_3_1_4__Vaska
{
	meta:
		author = "PEiD"
		description = "RCryptor 1.3 / 1.4 -> Vaska"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 55 8B EC 8B 44 24 04 83 E8 4F 68 ?? ?? ?? ?? FF D0 58 59 50 }
	condition:
		$a0
}

rule RCryptor1_3b__Vaska
{
	meta:
		author = "PEiD"
		description = "RCryptor 1.3b -> Vaska"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 61 83 EF 4F 60 68 ?? ?? ?? ?? FF D7 }
	condition:
		$a0
}

rule RCryptor1_5__Vaska
{
	meta:
		author = "PEiD"
		description = "RCryptor 1.5 -> Vaska"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 83 2C 24 4F 68 ?? ?? ?? ?? FF 54 24 04 83 44 24 04 4F }
	condition:
		$a0
}

rule RCryptor1_6__Vaska
{
	meta:
		author = "PEiD"
		description = "RCryptor 1.6 -> Vaska"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 33 D0 68 ?? ?? ?? ?? FF D2 }
	condition:
		$a0
}

rule RCryptor1_6b_1_6c__Vaska
{
	meta:
		author = "PEiD"
		description = "RCryptor 1.6b / 1.6c -> Vaska"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 }
	condition:
		$a0
}

rule RCryptor1_6d__Vaska
{
	meta:
		author = "PEiD"
		description = "RCryptor 1.6d -> Vaska"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 }
	condition:
		$a0
}

rule RCryptor1_xx__Vaska
{
	meta:
		author = "PEiD"
		description = "RCryptor 1.xx -> Vaska"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 90 58 90 50 90 8B 00 90 3C 50 90 58 0F 85 67 D6 EF 11 50 68 }
	condition:
		$a0
}

rule RCryptor2_0__Vaska
{
	meta:
		author = "PEiD"
		description = "RCryptor 2.0 -> Vaska"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 ?? 02 00 00 F7 D1 83 F1 FF 59 BA 32 21 ?? 00 F7 D1 83 F1 FF F7 D1 83 F1 FF 80 02 E3 F7 D1 83 F1 FF C0 0A 05 F7 D1 83 F1 FF 80 02 6F F7 D1 83 F1 FF 80 32 A4 F7 D1 83 F1 FF 80 02 2D F7 D1 83 F1 FF 42 49 85 C9 75 CD 1C 4F 8D 5B FD 62 1E 1C 4F 8D 5B FD 4D 9D B9 ?? ?? ?? 1E 1C 4F 8D 5B FD 22 1C 4F 8D 5B FD 8E A2 B9 B9 E2 83 DB E2 E5 4D CD 1E BF 60 AB 1F 4D DB 1E 1E 3D 1E 92 1B 8E DC 7D EC A4 E2 4D E5 20 C6 CC B2 8E EC 2D 7D DC 1C 4F 8D 5B FD 83 56 8E E0 3A 7D D0 8E 9D 6E 7D D6 4D 25 06 C2 AB 20 CC 3A 4D 2D 9D 6B 0B 81 45 CC 18 4D 2D 1F A1 A1 6B C2 CC F7 E2 4D 2D 9E 8B 8B CC DE 2E 2D F7 1E AB 7D 45 92 30 8E E6 B9 7D D6 8E 9D 27 DA FD FD 1E 1E 8E DF B8 7D CF 8E A3 4D 7D DC 1C 4F 8D 5B FD 33 D7 1E 1E 1E A6 0B 41 A1 A6 42 61 6B 41 6B 4C 45 1E 21 F6 26 BC E2 62 1E 62 1E 62 1E 23 63 59 ?? 1E 62 1E 62 1E 33 D7 1E 1E 1E 85 6B C2 41 AB C2 9F 23 6B C2 41 A1 1E C0 FD F0 FD 30 20 33 9E 1E 1E 1E 85 A2 0B 8B C2 27 41 EB A1 A2 C2 1E C0 FD F0 FD 30 62 1E 33 7E 1E 1E 1E C6 2D 42 AB 9F 23 6B C2 41 A1 1E C0 FD F0 FD 30 C0 FD F0 8E 1D 1C 4F 8D 5B FD E0 00 33 5E 1E 1E 1E BF 0B EC C2 E6 42 A2 C2 45 1E C0 FD F0 FD 30 CE 36 CC F2 1C 4F 8D 5B FD }
	condition:
		$a0
}

rule RE_Crypt0_7x__Crudd_RET
{
	meta:
		author = "PEiD"
		description = "RE-Crypt 0.7x -> Crudd / RET"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 61 60 E8 00 00 00 00 5D 55 81 04 24 0A 00 00 00 C3 8B F5 81 C5 ?? ?? 00 00 89 6D 34 89 75 38 8B 7D 38 81 E7 00 FF FF FF 81 C7 48 00 00 00 47 03 7D 60 8B 4D 5C 83 F9 00 7E 0F 8B }
	condition:
		$a0
}

rule RE_Crypt0_7x__Crudd_RET_
{
	meta:
		author = "PEiD"
		description = "RE-Crypt 0.7x -> Crudd / RET"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 55 81 04 24 0A 00 00 00 C3 8B F5 81 C5 ?? ?? 00 00 89 6D 34 89 75 38 8B 7D 38 81 E7 00 FF FF FF 81 C7 48 00 00 00 47 03 7D 60 8B 4D 5C 83 F9 00 7E 0F 8B 17 33 55 58 89 17 83 C7 04 83 C1 FC EB EC 8B }
	condition:
		$a0
}

rule USSR0_31_bySpirit
{
	meta:
		author = "PEiD"
		description = "USSR 0.31 - by Spirit"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { E8 00 00 00 00 5D 83 C5 12 55 C3 20 83 B8 ED 20 37 EF C6 B9 79 37 9E 8C C9 30 C9 E3 01 C3 BE 32 ?? ?? ?? B0 ?? 30 06 8A 06 46 81 FE 00 ?? ?? ?? 7C F3 }
	condition:
		$a0 at pe.entry_point
}

rule YZPack1_1__UsAr
{
	meta:
		author = "PEiD"
		description = "YZPack 1.1 -> UsAr"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 33 C0 8D 48 07 50 E2 FD 8B EC 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 8D 40 7C 8B 40 3C 89 45 04 E8 F3 07 00 00 60 8B 5D 04 8B 73 3C 8B 74 33 78 03 F3 56 8B 76 20 03 F3 33 C9 49 92 41 AD 03 C3 52 33 FF 0F B6 10 38 F2 }
	condition:
		$a0
}

rule YZPack1_2__UsAr
{
	meta:
		author = "PEiD"
		description = "YZPack 1.2 -> UsAr"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 4D 5A 52 45 60 83 EC 18 8B EC 8B FC 33 C0 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 83 C0 7C 8B 40 3C AB E9 ?? ?? ?? ?? B4 09 BA 00 00 1F CD 21 B8 01 4C CD 21 40 00 00 00 50 45 00 00 4C 01 02 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 E0 00 ?? ?? 0B 01 ?? ?? ?? ?? 00 00 }
	condition:
		$a0
}

rule YZPack2_0__UsAr
{
	meta:
		author = "PEiD"
		description = "YZPack 2.0 -> UsAr"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 87 25 ?? ?? ?? ?? 61 87 CC 55 45 45 55 81 ED CA 00 00 00 55 A4 B3 02 FF 14 24 73 F8 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 1F B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3C AA EB DC FF 54 24 04 2B CB 75 0F FF 54 24 08 EB 27 AC D1 E8 74 30 13 C9 EB 1B 91 48 C1 E0 08 AC FF 54 24 08 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 }
	condition:
		$a0
}

rule PolyCryptPE_2_1_4b_2_1_5__JLabSoftwareCreations
{
	meta:
		author = "PEiD"
		description = "PolyCrypt PE - 2.1.4b/2.1.5 -> JLab Software Creations"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 91 8B F4 AD FE C9 80 34 08 ?? E2 FA C3 60 E8 ED FF FF FF EB }
	condition:
		$a0 at pe.entry_point
}

rule PolyCryptPE_2_1_4b_2_1_5__JLabSoftwareCreations_
{
	meta:
		author = "PEiD"
		description = "PolyCrypt PE - 2.1.4b/2.1.5 -> JLab Software Creations"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 50 6F 6C 79 43 72 79 70 74 20 50 45 20 28 63 29 20 32 30 30 34 2D 32 30 30 35 2C 20 4A 4C 61 62 53 6F 66 74 77 61 72 65 2E 00 50 00 43 00 50 00 45 }
	condition:
		$a0 at pe.entry_point
}

rule SplashBitmap1_00_WithUnpackCode___BoB_TeamPEiD
{
	meta:
		author = "PEiD"
		description = "Splash Bitmap 1.00 (With Unpack Code) -> BoB / Team PEiD"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { E8 00 00 00 00 60 8B 6C 24 20 55 81 ED ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 29 F9 31 C0 FC F3 AA 8B 04 24 48 66 25 00 F0 66 81 38 4D 5A 75 F4 8B 48 3C 81 3C 01 50 45 00 00 75 E8 89 85 ?? ?? ?? ?? 6A 40 }
	condition:
		$a0
}

rule SplashBitmap1_00__BoB_TeamPEiD
{
	meta:
		author = "PEiD"
		description = "Splash Bitmap 1.00 -> BoB / Team PEiD"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { E8 00 00 00 00 60 8B 6C 24 20 55 81 ED ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 29 F9 31 C0 FC F3 AA 8B 04 24 48 66 25 00 F0 66 81 38 4D 5A 75 F4 8B 48 3C 81 3C 01 50 45 00 00 75 E8 89 85 ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 6A 00 }
	condition:
		$a0
}

rule AverCryptor1_02beta__os1r1s_
{
	meta:
		author = "PEiD"
		description = "AverCryptor 1.02 beta -> os1r1s"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 0C 17 40 00 8B BD 33 18 40 00 8B 8D 3B 18 40 00 B8 51 18 40 00 03 C5 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 37 18 40 00 33 C0 51 33 C9 66 B9 F7 00 66 83 F9 00 74 49 8B 57 0C 03 95 37 18 40 00 8B 85 3F 18 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 8B F1 E8 27 00 00 00 8B C8 5F B8 51 18 40 00 03 C5 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 2F 18 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 23 F7 8B C6 5F 5E C3 }
	condition:
		$a0
}

rule AverCryptor1_0__os1r1s_
{
	meta:
		author = "PEiD"
		description = "AverCryptor 1.0 -> os1r1s"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 75 17 40 00 8B BD 9C 18 40 00 8B 8D A4 18 40 00 B8 BC 18 40 00 03 C5 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 A0 18 40 00 33 C0 51 33 C9 66 B9 FA 00 66 83 F9 00 74 49 8B 57 0C 03 95 A0 18 40 00 8B 85 A8 18 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 8B F1 E8 27 00 00 00 8B C8 5F B8 BC 18 40 00 03 C5 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 98 18 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 23 F7 8B C6 5F 5E C3 }
	condition:
		$a0
}

/*
My stuff ..
*/
rule ObsidiumV1_3_5_3__ObsidiumSoftware
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.3.5.3 -> Obsidium Software"
		group = "Auto (fly)"
		function = "0"
	strings:
		$a0 = { EB 02 ?? ?? E8 2B 00 00 00 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 24 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 02 ?? ?? E8 }
	condition:
		$a0
}

rule peidb1x
{
	meta:
		author = "PEiD"
		description = "PEiD-Bundle 1.0x -> BoB / Team PEiD"
		group = "2003"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }
	condition:
		$a0
}

rule peidb102
{
	meta:
		author = "PEiD"
		description = "PEiD-Bundle 1.02 -> BoB / Team PEiD"
		group = "2003"
		function = "0"
	strings:
		$a0 = { 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }
	condition:
		$a0
}

rule peidb102dll
{
	meta:
		author = "PEiD"
		description = "PEiD-Bundle 1.02 DLL -> BoB / Team PEiD"
		group = "2003"
		function = "0"
	strings:
		$a0 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 00 08 00 39 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 }
	condition:
		$a0
}

rule Imploder1_04__BoB_Team_PEiD
{
	meta:
		author = "PEiD"
		description = "Imploder 1.04 -> BoB / Team PEiD"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 C8 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }
	condition:
		$a0
}

rule PluginToExe1_00__BoB_Team_PEiD
{
	meta:
		author = "PEiD"
		description = "PluginToExe 1.00 -> BoB / Team PEiD"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { E8 00 00 00 00 29 C0 5D 81 ED D1 40 40 00 50 FF 95 B8 40 40 00 89 85 09 40 40 00 FF 95 B4 40 40 00 89 85 11 40 40 00 50 FF 95 C0 40 40 00 8A 08 80 F9 22 75 07 50 FF 95 C4 40 40 00 89 85 0D 40 40 00 8B 9D 09 40 40 00 60 6A 00 6A 01 53 81 C3 ?? ?? ?? 00 FF D3 61 6A 00 68 44 69 45 50 FF B5 0D 40 40 00 6A 00 81 C3 ?? ?? ?? 00 FF D3 83 C4 10 FF 95 B0 40 40 00 }
	condition:
		$a0
}

rule PluginToExe1_01__BoB_Team_PEiD
{
	meta:
		author = "PEiD"
		description = "PluginToExe 1.01 -> BoB / Team PEiD"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { E8 00 00 00 00 29 C0 5D 81 ED C6 41 40 00 50 8F 85 71 40 40 00 50 FF 95 A5 41 40 00 89 85 6D 40 40 00 FF 95 A1 41 40 00 50 FF 95 B5 41 40 00 80 38 00 74 16 8A 08 80 F9 22 75 07 50 FF 95 B9 41 40 00 89 85 75 40 40 00 EB 6C 6A 01 8F 85 71 40 40 00 6A 58 6A 40 FF 95 A9 41 40 00 89 85 69 40 40 00 89 C7 68 00 08 00 00 6A 40 FF 95 A9 41 40 00 89 47 1C C7 07 58 00 00 00 C7 47 20 00 08 00 00 C7 47 18 01 00 00 00 C7 47 34 04 10 88 00 8D 8D B9 40 40 00 89 4F 0C 8D 8D DB 40 40 00 89 4F 30 FF B5 69 40 40 00 FF 95 95 41 40 00 FF 77 1C 8F 85 75 40 40 00 8B 9D 6D 40 40 00 60 6A 00 6A 01 53 81 C3 ?? ?? ?? 00 FF D3 61 6A 00 68 44 69 45 50 FF B5 75 40 40 00 6A 00 81 C3 ?? ?? 00 00 FF D3 83 C4 10 83 BD 71 40 40 00 00 74 10 FF 77 1C FF 95 AD 41 40 00 57 FF 95 AD 41 40 00 6A 00 FF 95 9D 41 40 00 }
	condition:
		$a0
}

/*
----------------------------
*/
rule BobPack1_00___BoB_Team_PEiD
{
	meta:
		author = "PEiD"
		description = "BobPack 1.00 --> BoB / Team PEiD"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 0C 24 89 CD 83 E9 06 81 ED ?? ?? ?? ?? E8 3D 00 00 00 89 85 ?? ?? ?? ?? 89 C2 B8 ?? ?? ?? ?? 8D 04 08 E8 E4 00 00 00 8B 70 04 01 D6 E8 76 00 00 00 E8 51 01 00 00 E8 01 01 00 00 B8 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 89 44 24 1C 61 50 31 C0 C3 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 8B }
	condition:
		$a0
}

rule EXEStealth2_74__WebToolMaster
{
	meta:
		author = "PEiD"
		description = "EXE Stealth 2.74 -> WebToolMaster"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { EB 00 EB 17 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 60 90 E8 00 00 00 00 5D }
	condition:
		$a0
}

rule EXEStealth2_76__WebToolMaster
{
	meta:
		author = "PEiD"
		description = "EXE Stealth 2.76 -> WebToolMaster"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { EB 65 45 78 65 53 74 65 61 6C 74 68 20 56 32 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 20 59 4F 55 52 20 41 44 20 48 45 52 45 21 50 69 52 41 43 59 20 69 53 20 41 }
	condition:
		$a0
}

