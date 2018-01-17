#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import six

import os
import sys
import argparse
import traceback
import pickle
import logging
import logging.handlers
import time

# for pop3
import poplib
import email
#import dateutil.tz
import datetime

# for gmail api
import httplib2
import apiclient
from apiclient import discovery
import oauth2client
from oauth2client import client
from oauth2client import tools
import base64


# https://developers.google.com/gmail/api/auth/scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.insert', 
          'https://www.googleapis.com/auth/gmail.labels']
CLIENT_SECRET_FILE = 'client_secret.json'
CREDENTIAL_FILE = 'gmail-importer.json'
#APPLICATION_NAME = 'Mail Importer for Gmail'
APPLICATION_NAME = "gmail-importer"

stdout_fmt = '%(asctime)s %(levelname)s %(name)s - %(message)s'
file_fmt   = '%(asctime)s %(process)d %(levelname)s %(name)s:%(funcName)s(%(filename)s:%(lineno)d) - %(message)s'

class Cache(object):
    pkl_name = APPLICATION_NAME + ".cache"
    def __init__(self, is_clear):
        if is_clear:
            self.ids = set()
        else:
            self.ids = self.load()
    def add(self, id):
        self.ids.add(id)
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

# pop3
def login(mail_server, mail_user, mail_pass, is_tls=False):
    if is_tls:
        M = poplib.POP3_SSL(mail_server)
    else:
        M = poplib.POP3(mail_server)
    M.user(mail_user)
    M.pass_(mail_pass)
    return M

def parse_subject_py2(msg):
    m_subject = msg.get('Subject')
    try:
        d_subject = email.header.decode_header(m_subject)
        subject = email.header.make_header(d_subject)
        subject = unicode(subject)
        return subject.encode('utf-8')
    except Exception as e: #email.errors.HeaderParseError UnicodeDecodeError
        logger.error("Failed to parse subject: %s (%s)" % (m_subject, traceback.format_exc))
        logger.debug("Exception: %s" % traceback.format_exc)
        return m_subject

def parse_date_py2(msg):
    m_date = msg.get('Date')
    t_date = email.utils.parsedate_tz(m_date)
    #tz = dateutil.tz.tzoffset(None, t_date[9])
    #d_date = datetime.datetime(*t_date[:6], tzinfo=tz)
    d_date = datetime.datetime(*t_date[:6])
    return d_date.isoformat()

def parse_message_py2(string):
    msg = email.message_from_string(string)
    date = parse_date_py2(msg)
    subject = parse_subject_py2(msg)
    return (date, subject)

# api
def get_credentials(flags, pi):
    """Gets valid user credentials from storage.
    
    If nothing has been stored, or if the stored credentials are invalid,
    the OAuth2 flow is completed to obtain the new credentials.
    
    Returns:
        Credentials, the obtained credential.
    """
    home_dir = os.path.expanduser('~')
    credential_dir = os.path.join(home_dir, '.credentials')
    if not os.path.exists(credential_dir):
        os.makedirs(credential_dir)
    credential_path = os.path.join(credential_dir, CREDENTIAL_FILE)
    
    store = oauth2client.file.Storage(credential_path)
    credentials = store.get()
    if not credentials or credentials.invalid:
        flow = oauth2client.client.flow_from_clientsecrets(CLIENT_SECRET_FILE, SCOPES)
        flow.user_agent = APPLICATION_NAME
        http = httplib2.Http(proxy_info=pi)
        credentials = oauth2client.tools.run_flow(flow, store, flags, http=http)
        logger.info('Storing credentials to ' + credential_path)
    return credentials

def get_service(flags, pi):
    credentials = get_credentials(flags, pi)
    http = httplib2.Http(proxy_info=pi)
    http = credentials.authorize(http)
    service = discovery.build('gmail', 'v1', http=http)
    return service

def create_label(service, label_name, mlv='show', llv='labelShow', user_id='me'):
    from apiclient import errors
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
        logging.info("Label '%s' doesn't exist, creating it", label)
    return id

def import_(service, msg, label_id=None, user_id='me'):
    labelids = ['INBOX','UNREAD', label_id]
    message = {'raw': base64.urlsafe_b64encode(msg), 'labelIds':labelids}
    result = service.users().messages().import_(
        userId = user_id,
        body=message
    ).execute()
    return result

def process_emails(args, cache, pi):
    # discovery gmail api
    service = get_service(args, pi)
    label_id = get_labelid(service, args.label)
    
    # pop3 login
    M = login(args.mail_server, args.mail_user, args.mail_pass, args.tls)
    numMessages = M.stat()[0]
    logger.info("POP3 server has %s messages." % numMessages)
    
    # get email, insert gmail
    try:
        for i in xrange(numMessages, 0, -1):
            uid = M.uidl(i).split()[2]
            if not cache.is_member(uid):
                msg = '\n'.join(M.retr(i)[1])
                d, s = parse_message_py2(msg)
                guid = import_(service, msg, label_id)['id'].encode('utf-8')
                meta = (i, uid, guid, d, s)
                logger.info("import: %s: %s: %s: %s" % (i, d, uid, s))
                logger.debug('JSON: {"seq_id":"%s", "uid":"%s", "guid":"%s", "date":"%s", "subject":"%s"}' % meta)
                # set its seen flag
                cache.add(uid)
            #raw_input("Type 'Ctrl+C' if you want to interrupt program.")
    except Exception as e:
        logger.exception('Failed to import messages')
        raise
    cache.dump()

def main():
    # load seen flag cache
    cache = Cache(args.nocache)
    
    # set proxyinfo
    pi = httplib2.ProxyInfo(httplib2.socks.PROXY_TYPE_HTTP, args.proxy_host, args.proxy_port)
    
    try:
        process_emails(args, cache, pi)
        while args.interval:
            time.sleep(args.interval)
            process_emails(args, cache, pi)
    except KeyboardInterrupt:
        # dump seen flag cache
        cache.dump()
        sys.exit("Crtl+C pressed. Shutting down.")
    except Exception as e:
        logger.exception('Unknown exception occured.')
        sys.exit("Unknown exception occured. Shutting down.")

    # dump seen flag cache
    cache.dump()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(parents=[tools.argparser], description='Mail Importer for Gmail will import your emails on a POP3-server to Gmail via Gmail API and HTTP-proxy, and puts UNREAD/INBOX labels on emails.')
    parser.add_argument('-l',   '--label',  action="store", default=os.getenv("IMPORTED_LABEL", "_imported"))
    parser.add_argument('-s',   '--mail_server',  action="store", default=os.getenv("MAIL_SERVER", 'localhost'))
    parser.add_argument('-u',   '--mail_user',  action="store", default=os.getenv("MAIL_USER"))
    parser.add_argument('-p',   '--mail_pass',  action="store", default=os.getenv("MAIL_PASS"))
    parser.add_argument('--tls',  action="store_true", help="Enable TLS/SSL for POP3 protocol")
    parser.add_argument('-ph',   '--proxy_host',  action="store", default=os.getenv("PROXY_HOST"))
    parser.add_argument('-pp',   '--proxy_port', action="store", type=int, default=os.getenv("PROXY_PORT"))
    parser.add_argument('-i', '--interval', action="store", type=int, default=None, help="Wait interval seconds between import process. Type Ctrl+c if you want stop program.")
    parser.add_argument('--nocache',  action="store_true", help="Ignore seen flag cache.")
    parser.add_argument('-d', '--debug',  action="store_true", help="Enable debug message.")
    parser.set_defaults(logging_level='INFO')

    args = parser.parse_args()

    # set logger
    _lvl = args.logging_level
    if args.debug:
        _lvl = logging.DEBUG
        httplib2.debuglevel = 4
    
    _cformatter = logging.Formatter(stdout_fmt)
    _ch = logging.StreamHandler()
    _ch.setLevel(logging.INFO)
    _ch.setFormatter(_cformatter)
    _file_formatter = logging.Formatter(file_fmt)
    _fh = logging.handlers.RotatingFileHandler(APPLICATION_NAME + '.log', maxBytes=1024 * 1024 * 8, backupCount=8)
    _fh.setLevel(logging.DEBUG)
    _fh.setFormatter(_file_formatter)
    logger = logging.getLogger(APPLICATION_NAME)
    logger.setLevel(_lvl)
    logger.addHandler(_ch)
    logger.addHandler(_fh)

    # 
    logger.debug(args)
    logger.debug('logging level: %s' % logger.getEffectiveLevel())

    main()
