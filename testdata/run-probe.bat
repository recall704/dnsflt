@echo off
cd /d C:\tmp\yogadns-re\dnsflt
C:\tmp\yogadns-re\dnsflt\target\release\examples\filter_probe2.exe > C:\tmp\yogadns-re\dnsflt\testdata\filter-probe2.log 2>&1
echo EXITCODE=%ERRORLEVEL% >> C:\tmp\yogadns-re\dnsflt\testdata\filter-probe2.log