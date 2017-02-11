set "_ADDomain=%USERDOMAIN%"
set "_ADUsername=%USERNAME%"
set "_ADAccount=%_ADDomain%\%_ADUsername%"
echo _ADAccount is %_ADAccount%

rem powershell ./LsaSecurity.ps1 -account %_ADAccount%