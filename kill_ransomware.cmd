:: Simple Active Response to Kill the Ransomware Process
:: Terminates python.exe and its child processes forcefully
taskkill /F /IM python.exe /T

:: Log the action for forensic verification
echo %date% %time% - Killed Ransomware Simulator >> "C:\active_response_log.txt"
