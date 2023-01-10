// 1st draft.  I'm not 100% sure if my offsets are correct.  Testing to follow soon.

rule Training_PMAT_Wannacry : WannaCry
{
meta:
	author = ""
	date = "2023-01-09"
	version = "1.0"
	hash = "db349b97c37d22f5ea1d1841e3c89eb4"
	daysOfYARA = "9/100"
strings:
	$WC = {57 41 4E 43 52 59 21} // WANACRY!
	$TS = {74 61 73 6B 73 63 68 65 2E 65 78 65} //tasksche.exe
condition:
	uint16(0) == 0x5A4D and
	uint16(0xB020) == 0x5A4D and
	uint16(0xF080) == 0x5A4D and
	all of them	
}
