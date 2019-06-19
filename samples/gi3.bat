@echo off
chcp 65001

set HTTP_PROXY='http://proxy.example.com:20066'
set HTTPS_PROXY='http://proxy.example.com:20066'
set MAIL_SERVER='your.mail.server.example.com'
set MAIL_USER='denden.taro@your.mail.server.example.com'
set MAIL_PASS='password'

cd /d %~dp0

REM gi3.exe -i 300 -l label --mail_proto=IMAP %*
:loop
  .\gi3.exe -l --mail_proto=IMAP --move -f %*
  timeout 60
goto :loop
