rule lab12exe
{
strings:
	$string1 = "InternetOpenUrlA"
	$string2 = "InternetOpenA" 
	$string3 ="OpenSCManagerA"
	$string4 = "ADVAAPI32.dll"
condition:
	filesize < 10MB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and ( $string1 or $string2 or $string3 or $string4)
}
