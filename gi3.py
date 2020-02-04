#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import traceback
import pickle
import logging
import logging.handlers
import time
import io
# pop/imap/emal
import poplib
import imaplib
import email
#import dateutil.tz
import datetime

# for gmail api
import httplib2
import googleapiclient
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import base64

# https://developers.google.com/gmail/api/auth/scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.insert', 
          'https://www.googleapis.com/auth/gmail.labels']
API_SERVICE_NAME = 'gmail'
API_VERSION = 'v1'
CLIENT_SECRETS_FILE = 'client_secret.json'
#CREDENTIAL_TOKEN_FILE = 'gi.json'
CREDENTIAL_TOKEN_FILE = 'gi.token.pickle'
#APPLICATION_NAME = 'Mail Importer for Gmail'
APPLICATION_NAME = "g-importer"
FILENAME = "gi"
USER_AGENT = 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.3; WOW64; Trident/7.0; Touch; .NET4.0E; .NET4.0C; .NET CLR 3.5.30729; .NET CLR 2.0.50727; .NET CLR 3.0.30729; Tablet PC 2.0)'

stdout_fmt = '%(asctime)s %(levelname)s %(name)s - %(message)s'
file_fmt   = '%(asctime)s %(process)d %(levelname)s %(name)s:%(funcName)s(%(filename)s:%(lineno)d) - %(message)s'
logger = logging.getLogger(APPLICATION_NAME)

class Cache(object):
    pkl_name = FILENAME + ".cache"
    def __init__(self, is_clear):
        if is_clear:
            self.ids = set()
        else:
            self.ids = self.load()
    def add(self, id):
        self.ids.add(id)
    def remove(self, id):
        self.ids.remove(id)
    def is_member(self, id):
        return id in self.ids
    def load(self):
        try:
            with open(self.pkl_name, mode="rb") as f:
                return pickle.load(f)
        except IOError as e:
            logger.error("IOError: %s" % e)
            return set()
    def dump(self):
        with open(self.pkl_name, mode="wb") as f:
            pickle.dump(self.ids, f)

# helpers
def set_logger(quiet, verbose, debug, colorize=True):
    _lvl = logging.INFO + 10*quiet - 10*verbose
    if debug:
        _lvl = logging.DEBUG
    _cformatter = logging.Formatter(stdout_fmt)
    _ch = logging.StreamHandler()
    _ch.setLevel(_lvl)
    _ch.setFormatter(_cformatter)
    _file_formatter = logging.Formatter(file_fmt)
    _fh = logging.handlers.RotatingFileHandler(FILENAME + '.log', maxBytes=1024 * 1024 * 4, backupCount=4)
    _fh.setLevel(logging.DEBUG)
    _fh.setFormatter(_file_formatter)
    logger = logging.getLogger(APPLICATION_NAME)
    logger.setLevel(_lvl)
    logger.addHandler(_ch)
    logger.addHandler(_fh)

# email
def parse_date(msg):
    m_date = msg['date']
    d_date = email.utils.parsedate_to_datetime(m_date)
    return d_date.astimezone().isoformat()

def parse_message(bytes: bytes):
    msg = email.message_from_bytes(bytes, policy=email.policy.SMTP)
    #msg = email.message_from_bytes(bytes, policy=email.policy.SMTPUTF8)
    date = parse_date(msg)
    subject = msg['subject']
    return (msg, date, subject)

# api gmail
def get_credentials(client_secret_file=CLIENT_SECRETS_FILE, scopes=SCOPES, token_file=CREDENTIAL_TOKEN_FILE):
    """
    Returns:
        Credentials, the obtained credential.
    """
    creds = None
    if os.path.exists(token_file):
        with open(token_file, 'rb') as token:
            creds = pickle.load(token)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                client_secret_file, scopes)
            creds = flow.run_local_server()
            #creds = flow.run_console()
        # Save the credentials for the next run
        with open(token_file, 'wb') as token:
            pickle.dump(creds, token)
    return creds

def get_service(creds, api_service_name=API_SERVICE_NAME, api_version=API_VERSION):
    service = build(api_service_name, api_version, credentials=creds)
    return service

def create_label(service, label_name, mlv='show', llv='labelShow', user_id='me'):
    from googleapiclient import errors
    label_object = {'messageListVisibility': mlv,
            'name': label_name,
            'labelListVisibility': llv}
    try:
        r = service.users().labels().create(userId=user_id,
                                              body=label_object).execute()
        logger.info(r)
        return r['id']
    except errors.HttpError as e:
        logger.info('Exception: %s' % e)
        logger.exception("Can't create label '%s' for user %s", label_name, user_id)
        raise

def get_labelid(service, label, user_id='me'):
    results = service.users().labels().list(userId=user_id).execute()
    labels = results.get('labels', [])
    d = [x for x in labels if x['name'] == label]
    if d != []:
        id = d[0]['id']
    else:
        id = create_label(service, label)
        logger.info("Label '{}' doesn't exist, creating it".format(label))
    return id

def import_(service, msg, mail, label_id=None, user_id='me'):
    labelids = ['INBOX', 'UNREAD', label_id]
    if len(msg)<5000000:
        raw = base64.urlsafe_b64encode(msg).decode('utf-8')
        message = {'raw': raw, 'labelIds': labelids}
        response = service.users().messages().import_(
            userId=user_id,
            body=message
        ).execute()
    elif len(msg)<30000000:
        # Use media upload to allow messages more than 5mb.
        # See https://developers.google.com/api-client-library/python/guide/media_upload
        # and http://google-api-python-client.googlecode.com/hg/docs/epy/apiclient.http.MediaIoBaseUpload-class.html.
        metadata_object = {'labelIds':labelids}
        try:
            #media = googleapiclient.http.MediaIoBaseUpload(io.StringIO(mail.as_string()), mimetype='message/rfc822')
            # if use io.BytesIO, then get UnicodeEncodeError('ascii' codec can't encode characters)
            media = googleapiclient.http.MediaIoBaseUpload(io.BytesIO(msg), mimetype='message/rfc822')
            response = service.users().messages().import_(
                userId=user_id,
                body=metadata_object,
                media_body=media,
            ).execute()
        except UnicodeEncodeError as e:
            logger.info("Catched '{}', then encode email data with 7 bit encoding".format(e))
            bytes = mail.as_bytes(policy=email.policy.default.clone(cte_type="7bit"))
            media = googleapiclient.http.MediaIoBaseUpload(io.BytesIO(bytes), mimetype='message/rfc822')
            response = service.users().messages().import_(
                userId=user_id,
                body=metadata_object,
                media_body=media,
            ).execute()
    else:
        metadata_object = {'labelIds':labelids}
        media = googleapiclient.http.MediaIoBaseUpload(io.StringIO(mail.as_string()), mimetype='message/rfc822', resumable=True)
        #media = googleapiclient.http.MediaIoBaseUpload(io.BytesIO(msg), mimetype='message/rfc822', resumable=True)
        request = service.users().messages().import_(
            userId=user_id,
            body=metadata_object,
            media_body=media
        )
        response = None
        while response is None:
            status, response = request.next_chunk()
            if status:
                logger.info("import status: {}%".format(int(status.progress() * 100)))
    return response

# pop3
def login_pop3(host, username, pass_, port=0, is_tls=False, is_debug=False):
    if is_tls:
        p = port if port else poplib.POP3_SSL_PORT
        M = poplib.POP3_SSL(host, port=p)
    else:
        p = port if port else poplib.POP3_PORT
        M = poplib.POP3(host, port=p)
    if is_debug:
        M.set_debuglevel(1)
    M.user(username)
    M.pass_(pass_)
    logger.info(M.getwelcome())
    return M

def process_emails_pop3(args, cache):
    # pop3 login
    M = login_pop3(args.mail_server, args.mail_user, args.mail_pass, args.tls, args.debug)
    numMessages = M.stat()[0]
    logger.info("POP3 server has {} messages.".format(numMessages))
    logger.debug("M.uidl: {}".format(M.uidl()))
    
    # return if there are no emails.
    if numMessages == 0:
        r = M.quit()
        logger.info(r)
        return
    
    # discovery gmail api
    try:
        service = get_service(get_credentials())
        label_id = get_labelid(service, args.label)
    except Exception as e:
        logger.exception('Failed to discovery gmail api')
        raise
    
    # get email, insert gmail
    try:
        for i in range(numMessages, 0, -1):
            try:
                uid = M.uidl(i).split()[2]
                logger.info("msg: {}: {}: {}".format(i, uid, M.uidl(i)))
                logger.debug("cache: {}".format(cache.ids))
                if cache.is_member(uid):
                    continue
                raw_msg_bytes = b'\r\n'.join(M.retr(i)[1])
                mail, d, s = parse_message(raw_msg_bytes)
                logger.info("parsed: {}: {}: {}: {}".format(i, uid, d, s))
                guid = import_(service, raw_msg_bytes, mail, label_id)['id'].encode('utf-8')
                logger.info("import: {}: {}: {}: {}: {}".format(i, uid, d, s, guid))
                # set its seen flag
                cache.add(uid)
                if args.delete:
                    M.dele(i)
                    logger.info("delete: %s: %s: %s: %s" % (i, d, uid, s))
                    cache.remove(uid)
            except googleapiclient.errors.HttpError as e:
                if not args.force:
                    raise
                logger.exception('Exception googleapiclient.errors.HttpError occured. Skip the email.')
                logger.warning('Ignore the exception and continue processing.')
                continue
            #input("Type 'Ctrl+C' if you want to interrupt program.")
    finally:
        # dump seen flag cache
        cache.dump()
        r = M.quit()
        logger.info(r)

# imap
def login_imap(host, user, password, port=0, is_tls=False, is_debug=False):
    if is_debug:
        imaplib.Debug = 4
    if is_tls:
        p = port if port else imaplib.IMAP4_SSL_PORT
        M = imaplib.IMAP4_SSL(host, port=p)
    else:
        p = port if port else imaplib.IMAP4_PORT
        M = imaplib.IMAP4(host, port=p)
    if 'AUTH=CRAM-MD5' in M.capabilities:
        typ, data = M.login_cram_md5(user, password)
    else:
        typ, data = M.login(user, password)
    logger.info("{} {}".format(typ, data))
    return M

def logout_imap(M, expunge=False):
    typ, data = M.expunge()
    logger.debug("imap: {} {}".format(typ, data))
    typ, data = M.close()
    logger.debug("imap: {} {}".format(typ, data))
    typ, data = M.logout()
    logger.debug("imap: {} {}".format(typ, data))

def move_mbox(M, uid, dst):
    # copy
    typ, data = M.uid('COPY', uid, dst)
    logger.debug("imap: {} {}".format(typ, data))
    # flag delete
    typ, data = M.uid('STORE', uid , '+FLAGS', '(\Deleted)')
    logger.debug("imap: {} {}".format(typ, data))
    
def process_emails_imap(args):
    # imap login
    M = login_imap(args.mail_server, args.mail_user, args.mail_pass, args.tls, args.debug)
    typ, data = M.list()
    logger.info("list mailboxes")
    for d in data:
        logger.info(d.decode('utf-8'))
    
    # get uids in mailbox (args.imap_src_mbox)
    M.select(args.imap_src_mbox)
    typ, data = M.uid('search', None, "ALL")
    if typ != "OK":
        logger.error("failed to imap search")
    uids = data[0].split()
    logger.info("IMAP server has {} messages in mailbox {}.".format(len(uids), args.imap_src_mbox))
    logger.debug("uids: {}".format(uids))
    
    # return if there are no emails.
    if len(uids) == 0:
        logout_imap(M, False)
        return
    
    # discovery gmail api
    try:
        service = get_service(get_credentials())
        label_id = get_labelid(service, args.label)
    except Exception as e:
        logger.exception('Failed to discovery gmail api')
        raise
    
    try:
        for uid in uids:
            try:
                typ, data = M.uid('fetch', uid, '(RFC822)')
                raw_msg_bytes = data[0][1]
                mail, d, s = parse_message(raw_msg_bytes)
                logger.info("parsed: {}: {}: {}".format(uid, d, s))
                guid = import_(service, raw_msg_bytes, mail, label_id)['id'].encode('utf-8')
                logger.info("import: {}: {}: {}: {}".format(uid, d, s, guid))
                if args.move:
                    move_mbox(M, uid, args.imap_dst_mbox)
            except googleapiclient.errors.HttpError as e:
                if not args.force:
                    raise
                logger.exception('Exception googleapiclient.errors.HttpError occured. Skip the email.')
                logger.warning('Ignore the exception and continue processing.')
                continue
            #input("Type 'Ctrl+C' if you want to interrupt program.")
    finally:
        logout_imap(M, True)

def main():
    # load seen flag cache
    
    if args.mail_proto == 'POP3':
        cache = Cache(args.nocache)
        process_emails = lambda args, cache=cache: process_emails_pop3(args, cache)
    elif args.mail_proto == 'IMAP':
        process_emails = process_emails_imap
    else:
        raise Exception("Unknown protocol")
    
    while args.interval:
        try:
            process_emails(args)
            logger.info("waiting interval...")
            time.sleep(args.interval)
        except KeyboardInterrupt:
            sys.exit("Crtl+C pressed. Shutting down.")
    else:
        process_emails(args)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Mail Importer for Gmail will import your emails on a POP3/IMAP-server to Gmail via Gmail API and HTTP-proxy, and puts UNREAD/INBOX labels on emails. It supports HTTP_PROXY/HTTPS_PROXY.')
    parser.add_argument('-l', '--label',  action="store", default=os.getenv("IMPORTED_LABEL", "_imported"))
    parser.add_argument('--mail_server',  action="store", default=os.getenv("MAIL_SERVER", 'localhost'))
    parser.add_argument('--mail_port',  action="store", type=int, default=os.getenv("MAIL_PORT", 0))
    parser.add_argument('--mail_proto',  action="store", default=os.getenv("MAIL_PROTOCOL", 'POP3'), choices=['POP3', 'IMAP'])
    parser.add_argument('--mail_user',  action="store", default=os.getenv("MAIL_USER"))
    parser.add_argument('--mail_pass',  action="store", default=os.getenv("MAIL_PASS"))
    parser.add_argument('--imap_src_mbox',  action="store", default=os.getenv("IMAP_SRC_MBOX", "INBOX"))
    parser.add_argument('--imap_dst_mbox',  action="store", default=os.getenv("IMAP_DST_MBOX", "_imported"), help="destination imap mailbox")
    parser.add_argument('--move',  action="store_true", help="Move imported messages into the destination mailbox")
    parser.add_argument('--delete',  action="store_true", help="Delete imported messages")
    parser.add_argument('--tls',  action="store_true", help="Enable TLS/SSL for POP3/IMAP protocol")
    parser.add_argument('-i', '--interval', action="store", type=int, default=None, help="Wait interval seconds between import process. Type Ctrl+c if you want stop program.")
    parser.add_argument('-f', '--force', action="store_true", help="Ignore the exception and continue the import process, if used with the -i option.")
    parser.add_argument('--nocache',  action="store_true", help="Ignore seen flag cache.")
    parser.add_argument('-v', '--verbose', action='count', default=0, help="Make the operation more talkative")
    parser.add_argument('-q', '--quiet', action='count', default=0, help="Quiet mode")
    parser.add_argument('-d', '--debug',  action="store_true", help="Enable debug message.")
    args = parser.parse_args()

    # set logger
    set_logger(args.quiet, args.verbose, args.debug)
    if args.debug:
        httplib2.debuglevel = 1 + args.verbose

    logger.debug(args)
    logger.debug('logging level: %s' % logger.getEffectiveLevel())

    main()
