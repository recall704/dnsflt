@echo off
REM Elevated launcher: capture dnsflt stdout/stderr so we can see why it exits.
cd /d C:\tmp\yogadns-re\dnsflt
C:\tmp\yogadns-re\dnsflt\target\release\dnsflt.exe -c C:\tmp\yogadns-re\dnsflt\testdata\e2e.toml run > C:\tmp\yogadns-re\dnsflt\testdata\e2e-stdout.log 2>&1
echo EXITCODE=%ERRORLEVEL% >> C:\tmp\yogadns-re\dnsflt\testdata\e2e-stdout.log