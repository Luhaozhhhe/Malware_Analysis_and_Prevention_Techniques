rule Lab03_02 {
   meta:
      description = " - file Lab03-02.dll"
      author = "Luhaozhhhe"
      date = "2024-10-03"
      hash1 = "5eced7367ed63354b4ed5c556e2363514293f614c2c2eb187273381b2ef5f0f9"
   strings:
      $s1 = "%SystemRoot%\\System32\\svchost.exe -k " fullword ascii
      $s2 = "cmd.exe /c " fullword ascii
      $s3 = "RegOpenKeyEx(%s) KEY_QUERY_VALUE error ." fullword ascii
      $s4 = "Lab03-02.dll" fullword ascii
      $s5 = "practicalmalwareanalysis.com" fullword ascii
      $s6 = "RegOpenKeyEx(%s) KEY_QUERY_VALUE success." fullword ascii
      $s7 = "GetModuleFileName() get dll path" fullword ascii
      $s8 = "dW5zdXBwb3J0" fullword ascii /* base64 encoded string 'unsupport' */
      $s9 = "Y29ubmVjdA==" fullword ascii /* base64 encoded string 'connect' */
      $s10 = "CreateService(%s) error %d" fullword ascii
      $s11 = "Internet Network Awareness" fullword ascii
      $s12 = "RegQueryValueEx(Svchost\\netsvcs)" fullword ascii
      $s13 = "netsvcs" fullword ascii
      $s14 = "serve.html" fullword ascii
      $s15 = "svchost.exe" fullword ascii
      $s16 = "IPRIP" fullword ascii
      $s17 = "uninstall is starting" fullword ascii
      $s18 = "uninstall success" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      6 of them
}