@echo off
chcp 65001

set PROXY_HOST='proxy.example.com'
set PROXY_PORT=20066
set MAIL_SERVER='your.pop3.server.example.com'
set MAIL_USER='denden.taro@your.pop3.server.example.com'
set MAIL_PASS='password'

cd /d %~dp0
gi.exe -i 300 -l @lab.ntt.co.jp %*
