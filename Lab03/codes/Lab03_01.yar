rule Lab03_01 {
   meta:
      description = " - file Lab03-01.exe"
      author = "Luhaozhhhe"
      date = "2024-10-03"
      hash1 = "eb84360ca4e33b8bb60df47ab5ce962501ef3420bc7aab90655fd507d2ffcedd"
   strings:
      $s1 = "vmx32to64.exe" fullword ascii
      $s2 = "SOFTWARE\\Classes\\http\\shell\\open\\commandU" fullword ascii
      $s3 = " www.practicalmalwareanalysis.com" fullword ascii
      $s4 = "CONNECT %s:%i HTTP/1.0" fullword ascii
      $s5 = "advpack" fullword ascii
      $s6 = "VideoDriver" fullword ascii
      $s7 = "AppData" fullword ascii
      $s8 = "advapi32" fullword ascii 
      $s9 = "ntdll" fullword ascii 
      $s10 = "WinVMX32-" fullword ascii
      $s11 = "Software\\Microsoft\\Active Setup\\Installed Components\\test" fullword ascii
      $s12 = "ws2_32" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and 8 of them
}