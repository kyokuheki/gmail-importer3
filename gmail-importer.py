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

APPLICATION_NAME = "gmail-importer"

# https://developers.google.com/gmail/api/auth/scopes
#SCOPES = ['https://www.googleapis.com/auth/gmail.insert', 'https://www.googleapis.com/auth/gmail.readonly']
SCOPES = ['https://www.googleapis.com/auth/gmail.insert', 
          'https://www.googleapis.com/auth/gmail.labels']
CLIENT_SECRET_FILE = 'client_secret.json'
CREDENTIAL_FILE = 'gmail-importer.json'
APPLICATION_NAME = 'Mail Importer for Gmail'

_fmt = '[%(asctime)s] %(levelname)-8s:%(name)s:%(funcName)s.%(lineno)d - %(message)s'
#_fmt = '%(created)f %(name)s[%(process)d]: %(levelname)s: %(filename)s.%(funcName)s.%(lineno)d - %(message)s'
#_fmt = '%(created)f %(name)s[%(process)d]: %(levelname)s: %(module)s.%(funcName)s.%(lineno)d - %(message)s'

#logging.basicConfig(format=_fmtcolor, level=lvl)
#_formatter = logging.Formatter(_fmtcolor)
#ch = logging.StreamHandler()
#ch.setLevel(lvl)
#ch.setFormatter(_formatter)
#logger = logging.getLogger(__name__)
#logger.setLevel(lvl)
#logger.addHandler(ch)

class Cache(object):
    pkl_name = APPLICATION_NAME + ".cache"
    def __init__(self, is_cache):
        if is_cache:
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
    except email.errors.HeaderParseError as e:
        logger.error("%s: %s" % (e, m_subject))
        return m_subject
    except UnicodeDecodeError as e:
        logger.error("%s: %s" % (e, m_subject))
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
    #print(msg.get('Message-Id'))
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
        print('Storing credentials to ' + credential_path)
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
        logging.exception("Can't create label '%s' for user %s", label_name, user_id)
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

def main(flags):
    # load seen flag cache
    cache = Cache(flags.cache)
    
    # set proxyinfo
    pi = httplib2.ProxyInfo(httplib2.socks.PROXY_TYPE_HTTP, flags.proxy_host, flags.proxy_port)
    
    # discovery gmail api
    service = get_service(flags, pi)
    label_id = get_labelid(service, flags.label)
    
    # pop3 login
    M = login(flags.mail_server, flags.mail_user, flags.mail_pass, flags.tls)
    numMessages = M.stat()[0]
    print("# of messages: %s" % numMessages)
    
    # get email, insert gmail
    try:
        for i in range(numMessages):
            uid = M.uidl(i+1).split()[2]
            if not cache.is_member(uid):
                msg = '\n'.join(M.retr(i+1)[1])
                d, s = parse_message_py2(msg)
                r = import_(service, msg, label_id)
                meta = (i+1, uid, r['id'].encode('utf-8'), d, s)
                print("%s:%s:%s:%s:\t%s" % meta)
                logger.info('imported: {"seq_id":"%s", "uid":"%s", "guid":"%s", "date":"%s", "subject":"%s"' % meta)
                # set its seen flag
                cache.add(uid)
            #raw_input("Type 'Ctrl+C' if you want to interrupt program.")
    except KeyboardInterrupt:
        # dump seen flag cache
        cache.dump()
        sys.exit("Crtl+C pressed. Shutting down.")
    
    # dump seen flag cache
    cache.dump()
    exit()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(parents=[tools.argparser], description='Mail Importer for Gmail')
    #parser.add_argument('infile', nargs='?', type=argparse.FileType('r'), default=sys.stdin, help="pop3 to Gmail with Gmail API")
    parser.add_argument('-l',   '--label',  action="store", default=os.getenv("IMPORTED_LABEL", "_imported"))
    parser.add_argument('-c',   '--cache',  action="store_true")
    parser.add_argument('-s',   '--mail_server',  action="store", default=os.getenv("MAIL_SERVER", 'localhost'))
    parser.add_argument('-u',   '--mail_user',  action="store", default=os.getenv("MAIL_USER"))
    parser.add_argument('-p',   '--mail_pass',  action="store", default=os.getenv("MAIL_PASS"))
    parser.add_argument('--tls',  action="store_true", help="enable TLS/SSL")
    parser.add_argument('-ph',   '--proxy_host',  action="store", default=os.getenv("PROXY_HOST"))
    parser.add_argument('-pp',   '--proxy_port',  action="store", default=os.getenv("PROXY_PORT"))
    parser.add_argument('-d', '--debug',  action="store_true", help="enable debug message")
    args = parser.parse_args()

    _lvl = args.logging_level
    if args.debug:
        _lvl = logging.DEBUG
        httplib2.debuglevel = 4
    
    _formatter = logging.Formatter(_fmt)
    _ch = logging.StreamHandler()
    _ch.setLevel(_lvl)
    _ch.setFormatter(_formatter)
    logger = logging.getLogger(APPLICATION_NAME)
    logger.setLevel(_lvl)
    logger.addHandler(_ch)

    logger.debug(args)
    logger.info('logging level: %s' % logger.getEffectiveLevel())

    main(args)
