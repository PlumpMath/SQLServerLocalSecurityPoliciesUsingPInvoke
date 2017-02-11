set "_ADDomain=%USERDOMAIN%"
set "_ADUsername=%USERNAME%"
set "_host=%COMPUTERNAME%"
set "_ADAccount=%_ADDomain%\%_host%$"
echo _ADAccount is %_ADAccount%

powershell ./LsaSecurity.ps1 -account %_ADAccount%