@echo off

set PYTHONHOME=C:\Python27
set PATH=C:\Python27\;C:\Python27\Scripts;C:\windows\system32;C:\windows;C:\windows\System32\Wbem;C:\windows\System32\WindowsPowerShell\v1.0\;

cd /d %~dp0

pip install --upgrade google-api-python-client
pip install --upgrade pyinstaller
pyinstaller --clean --onefile --log-level=WARN gi.py

@taskkill /IM gi.exe
@move /Y dist\gi.exe .\
@rmdir /S .\build
@rmdir /S .\dist
pause
