# Mail Importer for Gmail
Unusable security is not security.

Mail Importer for Gmail will import your emails on a POP3/IMAP-server in closed network to Gmail via Gmail API and HTTP-proxy, and puts UNREAD/INBOX labels on emails.
It supports HTTP_PROXY/HTTPS_PROXY.

## Install
1. Package install
```sh
pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib
```

2. Turn on the Gmail API and move *Credentials* file to your working directory and rename it `client_secret.json`
    - https://console.developers.google.com/apis/library/gmail.googleapis.com/
    - https://developers.google.com/gmail/api/quickstart/python

3. Edit gi3.sh

4. To start the gmail-importer, run the following command (one line):
```
export HTTP_PROXY='http://proxy..example.com:8080'
export HTTPS_PROXY=$HTTP_PROXY
./gi3.sh
```

## Build exe file
```
pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib
pip install --upgrade pyinstaller
pyinstaller --clean --onefile --log-level=WARN gi3.py
```

## Usage
```
$ python3 gi3.py -h
usage: gi3.py [-h] [--auth_host_name AUTH_HOST_NAME]
              [--noauth_local_webserver]
              [--auth_host_port [AUTH_HOST_PORT [AUTH_HOST_PORT ...]]]
              [--logging_level {DEBUG,INFO,WARNING,ERROR,CRITICAL}] [-l LABEL]
              [--mail_server MAIL_SERVER] [--mail_port MAIL_PORT]
              [--mail_proto {POP3,IMAP}] [--mail_user MAIL_USER]
              [--mail_pass MAIL_PASS] [--imap_src_mbox IMAP_SRC_MBOX]
              [--imap_dst_mbox IMAP_DST_MBOX] [--move] [--delete] [--tls]
              [-i INTERVAL] [-f] [--nocache] [-v] [-q] [-d]

Mail Importer for Gmail will import your emails on a POP3/IMAP-server to Gmail
via Gmail API and HTTP-proxy, and puts UNREAD/INBOX labels on emails. It
supports HTTP_PROXY/HTTPS_PROXY.

optional arguments:
  -h, --help            show this help message and exit
  --auth_host_name AUTH_HOST_NAME
                        Hostname when running a local web server.
  --noauth_local_webserver
                        Do not run a local web server.
  --auth_host_port [AUTH_HOST_PORT [AUTH_HOST_PORT ...]]
                        Port web server should listen on.
  --logging_level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Set the logging level of detail.
  -l LABEL, --label LABEL
  --mail_server MAIL_SERVER
  --mail_port MAIL_PORT
  --mail_proto {POP3,IMAP}
  --mail_user MAIL_USER
  --mail_pass MAIL_PASS
  --imap_src_mbox IMAP_SRC_MBOX
  --imap_dst_mbox IMAP_DST_MBOX
                        destination imap mailbox
  --move                Move imported messages into the destination mailbox
  --delete              Delete imported messages
  --tls                 Enable TLS/SSL for POP3/IMAP protocol
  -i INTERVAL, --interval INTERVAL
                        Wait interval seconds between import process. Type
                        Ctrl+c if you want stop program.
  -f, --force           Ignore the exception and continue the import process,
                        if used with the -i option.
  --nocache             Ignore seen flag cache.
  -v, --verbose         Make the operation more talkative
  -q, --quiet           Quiet mode
  -d, --debug           Enable debug message.
```
