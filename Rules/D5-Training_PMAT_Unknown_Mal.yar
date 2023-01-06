rule Training_PMAT_Unknown_Mal 
{
	meta:
		author = "ДАЗ"
		description = "Detection for Unknown Malware used in Lab 1.1 of TCM Security's PMAT course"
		Version = "1.0"
		hash = "1d8562c0adcaee734d63f7baaca02f7c"
		DaysOfYARA = "5/100"
	strings:
		$payload = "CR433101.dat.exe" ascii wide
		$url1 = "http://ssl-6582datamanager.helpdeskbros.local" ascii wide
		$url2 = "http://huskyhacks.dev" ascii wide
		$source_env = { 48 75 73 6B [14] 6C 64 65 76 }
	condition:
		uint16(0) == 0x5A4D and
		$payload and
		1 of ($url*) and
		$source_env
}
