@echo off

set PYTHONHOME=C:\Python37
set PATH=C:\Python37\;C:\Python37\Scripts;C:\windows\system32;C:\windows;C:\windows\System32\Wbem;C:\windows\System32\WindowsPowerShell\v1.0\;

cd /d %~dp0

pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib
pip install --upgrade pyinstaller
pyinstaller --clean --onefile --log-level=WARN gi3.py

@taskkill /IM gi3.exe
@move /Y dist\gi3.exe .\
@rmdir /S .\build
@rmdir /S .\dist
pause
