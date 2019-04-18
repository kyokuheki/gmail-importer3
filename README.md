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

3. To start the gmail-importer3, run the following command:
```
export HTTP_PROXY='http://proxy.example.com:20066'
export HTTPS_PROXY=$HTTP_PROXY
export MAIL_SERVER='your.mail.server.example.com'
export MAIL_USER='denden.taro@your.mail.server.example.com'
export MAIL_PASS='password'
# IMAP
export MAIL_PROTOCOL=IMAP
python3 gi3.py -l gmail_imported_label --move
# POP3
export MAIL_PROTOCOL=POP3
python3 gi3.py -l gmail_imported_label --delete
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

## Reference
- https://docs.python.org/ja/3.8/library/imaplib.html
- https://yuji.wordpress.com/2011/06/22/python-imaplib-imap-example-with-gmail/
- https://codeday.me/jp/qa/20190122/179684.html
- https://qiita.com/stkdev/items/a44976fb81ae90a66381
- https://www.programcreek.com/python/example/2875/imaplib.IMAP4_SSL
- https://stackoverflow.com/questions/3527933/move-an-email-in-gmail-with-python-and-imaplib
- https://qiita.com/renny1398/items/bcfd57c15cfb7c63326b

## Snippets

### imaplib

```python
import imaplib, email, email.policy
SERVER="your.mail.server.com"
USER="username"
PASS="password"
DST_MAILBOX = "_imported"

# login
M = imaplib.IMAP4(SERVER)
M.login(USER, PASS)

# list mailboxs
typ, data = M.list()
for d in data:
    print(d.decode('utf-8'))

# count and get emails in INBOX
## select mailbox
M.select('INBOX')
## get UIDs of emails
typ, data = M.uid('search', None, "ALL")
uids = data[0].split()
if typ == "OK":
    print("IMAP server has {} messages: {}".format(len(uids)))
    print("UIDS: {}".format(uids))
else:
    print("failed to open INBOX")

## get emails in INBOX and move to DST_MAILBOX using UID
for uid in uids:
    # get email bytes: IMAP FETCH Command's data item "RFC822" is same to POP3 RETR command
    # see RFC3501 sec 6.4.5 data item "RFC822"  https://tools.ietf.org/html/rfc3501#section-6.4.5
    typ, data = M.uid('fetch', uid, '(RFC822)')
    msg_raw_bytes = data[0][1]
    # parse email message bytes
    msg = email.message_from_bytes(msg_raw_bytes, policy=email.policy.SMTPUTF8)
    subject = msg['subject']
    print('Message {}: {}'.format(str(uid), subject))
    # copy the email to mailbox DST_MAILBOX
    typ, data = M.uid('COPY', uid, DST_MAILBOX)
    print(typ, data)
    # set deleted flag to the email in INBOX
    typ, data = M.uid('STORE', uid , '+FLAGS', '(\Deleted)')
    print(typ, data)
    # delete the email in INBOX
    typ, data = M.expunge()
    print(typ, data)

## fetch some data items
uid = uids[0]
typ, data = M.uid('fetch', uid, '(UID RFC822 BODY[TEXT])')
rfc822 = data[0][1]
body = data[1][1]
print(data[0][0]) # -> (UID #### RFC822 {XXXXX}
print(data[1][0]) # -> BODY[TEXT] {XXXX}
print(data[2][0]) # -> )
print(rfc822)
print(body)

# close mailbox and logout
M.close()
M.logout()
```

## poplib

```python
import poplib, email, email.policy
SERVER="your.mail.server.com"
USER="username"
PASS="password"

# login
M = poplib.POP3(SERVER)
M.set_debuglevel(1)
M.user(USER)
M.pass_(PASS)
print(M.getwelcome())

# count email
numMessages = M.stat()[0]
print("POP3 server has {} messages: {}".format(numMessages))

# get email subjects
for i in range(numMessages, 0, -1):
    # get the email UID
    uid = M.uidl(i).split()[2]
    # get email bytes using POP3 RETR Command
    msg_raw_bytes = b'\r\n'.join(M.retr(i)[1])
    # parse email message bytes
    msg = email.message_from_bytes(msg_raw_bytes, policy=email.policy.SMTPUTF8)
    subject = msg['subject']
    print('Message {}: {}'.format(str(uid), subject))
    # set deleted flag to the email
    M.dele(i)

# quit POP3 session and purge deleted emails
r = M.quit()
print(r)
```

## gi

```python
import gi3, logging
gi3.logger = logging.getLogger("test")
MIMAP = gi3.login_imap("your.mail.server.com", "username", "password", is_debug=True)
MPOP3 = gi3.login_pop3("your.mail.server.com", "username", "password", is_debug=True)
```
