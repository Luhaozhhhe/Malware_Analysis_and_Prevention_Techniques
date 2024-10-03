rule Lab03_04 {
   meta:
      description = " - file Lab03-04.exe"
      author = "Luhaozhhhe"
      date = "2024-10-03"
      hash1 = "6ac06dfa543dca43327d55a61d0aaed25f3c90cce791e0555e3e306d47107859"
   strings:
      $s1 = "http://www.practicalmalwareanalysis.com" fullword ascii
      $s2 = "%SYSTEMROOT%\\system32\\" fullword ascii
      $s3 = " HTTP/1.0" fullword ascii
      $s4 = " Manager Service" fullword ascii
      $s5 = "UPLOAD" fullword ascii 
      $s6 = "DOWNLOAD" fullword ascii 
      $s7 = "command.com" fullword ascii 
      $s8 = "-cc" fullword ascii 
      $s9 = "-re" fullword ascii 
      $s10 = "SOFTWARE\\Microsoft \\XPS" fullword ascii
      $s11 = "cmd.exe" fullword ascii
      $s12 = " >> NUL" fullword ascii
      $s13 = "-in" fullword ascii
      $s14 = "ShellExecuteA" fullword ascii

   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      7 of them
}