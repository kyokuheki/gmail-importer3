export HTTP_PROXY='http://proxy.example.com:20066'
export HTTPS_PROXY=$HTTP_PROXY
export MAIL_SERVER='your.mail.server.example.com'
export MAIL_USER='denden.taro@your.mail.server.example.com'
export MAIL_PASS='password'

python3 gi3.py -i 300 --mail_proto=IMAP $*
