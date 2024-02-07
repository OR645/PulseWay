$VelociraptorHTML = Invoke-WebRequest -Uri 'https://www.mediafire.com/file/9pprj3k9sep38fe/Org_S.B._velociraptor-v0.7.1.msi/file' -UseBasicParsing
$WindowsSensorHTML = Invoke-WebRequest -Uri 'https://www.mediafire.com/file/li7j3yym1v1i572/WindowsSensor.exe/file' -UseBasicParsing

$Velociraptor = ($VelociraptorHTML.Content | Select-String -Pattern 'href="(https://download.+?)"' -AllMatches | ForEach-Object { $_.Matches.Value }).Trim("href=").Trim('"')
$WindowsSensor = ($WindowsSensorHTML.Content | Select-String -Pattern 'href="(https://download.+?)"' -AllMatches | ForEach-Object { $_.Matches.Value }).Trim("href=").Trim('"')

msiexec /i "$velociraptor" /qb ALLUSERS=1 
cmd /c "$WindowsSensor" /install /quiet /norestart CID=B663970D9FA749759E9DA4FD289BE1AB-14
