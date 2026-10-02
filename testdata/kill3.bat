@echo off
cd /d C:\tmp\yogadns-re\dnsflt\testdata
taskkill /F /IM dnsflt.exe > kill.done 2>&1
echo EXITCODE=%ERRORLEVEL% >> kill.done