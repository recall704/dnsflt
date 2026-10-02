@echo off
REM Elevated launcher #2: upstream = 192.168.0.1:1153
cd /d C:\tmp\yogadns-re\dnsflt
C:\tmp\yogadns-re\dnsflt\target\release\dnsflt.exe -c C:\tmp\yogadns-re\dnsflt\testdata\e2e2.toml run > C:\tmp\yogadns-re\dnsflt\testdata\e2e2-stdout.log 2>&1
echo EXITCODE=%ERRORLEVEL% >> C:\tmp\yogadns-re\dnsflt\testdata\e2e2-stdout.log