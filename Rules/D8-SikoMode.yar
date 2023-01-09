rule Training_PMAT_SikoMode
{
	meta:
		author = "ДАЗ"
		description = "Detection of the naughty stealer that wants to exfiltrate a copy of a picture of Cosmo the cat"
		date = "2023-01-08"
		version = "1.0"
		hash = "b9497ffb7e9c6f49823b95851ec874e3"
		daysOfYARA = "8/100"
	
	strings:
		$passwrd = "SikoMode" ascii wide
		$exfil_url = "cdn.altimiter.local/feed" ascii wide
		
	condition:
		uint16(0) == 0x5A4D and
		$passwrd and
		$exfil_url
}
