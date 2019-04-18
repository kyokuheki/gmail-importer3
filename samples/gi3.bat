@echo off
chcp 65001

set HTTP_PROXY='http://proxy.example.com:20066'
set HTTPS_PROXY='http://proxy.example.com:20066'
set MAIL_SERVER='your.mail.server.example.com'
set MAIL_USER='denden.taro@your.pop3.server.example.com'
set MAIL_PASS='password'

cd /d %~dp0
gi3.exe -i 300 -l label --mail_proto=IMAP %*
