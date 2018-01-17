# Mail Importer for Gmail
Unusable security is not security.

Mail Importer for Gmail will import your emails on a POP3-server in closed network to Gmail via Gmail API and HTTP-proxy, and puts UNREAD/INBOX labels on emails.

## Install
1. Package install
```sh
pip install --upgrade google-api-python-client
```

2. Turn on the Gmail API and move *Credentials* file to your working directory and rename it `client_secret.json`
    - https://console.developers.google.com/apis/library/gmail.googleapis.com/
    - https://developers.google.com/gmail/api/quickstart/python

3. Edit gmail-importer.sh

4. To start the gmail-importer, run the following command (one line):
```
./gmail-importer.sh
```

## Usage
```
$ python2 gmail-importer.py -h
usage: gmail-importer.py [-h] [--auth_host_name AUTH_HOST_NAME]
                         [--noauth_local_webserver]
                         [--auth_host_port [AUTH_HOST_PORT [AUTH_HOST_PORT ...]]]
                         [--logging_level {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                         [-l LABEL] [-s MAIL_SERVER] [-u MAIL_USER]
                         [-p MAIL_PASS] [--tls] [-ph PROXY_HOST]
                         [-pp PROXY_PORT] [-i INTERVAL] [--nocache] [-d]

Mail Importer for Gmail

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
  -s MAIL_SERVER, --mail_server MAIL_SERVER
  -u MAIL_USER, --mail_user MAIL_USER
  -p MAIL_PASS, --mail_pass MAIL_PASS
  --tls                 Enable TLS/SSL for POP3 protocol
  -ph PROXY_HOST, --proxy_host PROXY_HOST
  -pp PROXY_PORT, --proxy_port PROXY_PORT
  -i INTERVAL, --interval INTERVAL
                        Wait interval seconds between import process. Type
                        Ctrl+c if you want stop program.
  --nocache             Ignore seen flag cache.
  -d, --debug           Enable debug message.

```
