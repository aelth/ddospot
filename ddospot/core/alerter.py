import collections
import datetime
import geoip
import logging
import os
import smtplib
import socket
import threading
import time

from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


class Alerter(object):
    def __init__(self, conf, name):
        self.name = name
        self.logger = logging.getLogger(name)
        mail_host = conf.get('alerting', 'mail_host')
        mail_port = conf.getint('alerting', 'mail_port')
        mail_username = conf.get('alerting', 'mail_username')
        mail_password = conf.get('alerting', 'mail_password')
        mail_sec = conf.get('alerting', 'mail_sec')
        if mail_sec == 'None':
            mail_sec = None
        self.mail_from = conf.get('alerting', 'mail_from')
        self.mail_to_list = [e.strip() for e in conf.get('alerting', 'mail_to').split(',')]
        self.mail_subject = conf.get('alerting', 'mail_subject')
        self.trigger_country_list = [e.strip() for e in conf.get('alerting', 'trigger_countries').split(',')]
        self.notification_rate = conf.getint('alerting', 'notification_rate')
        self.notification_allowance = float(self.notification_rate)
        self.last_notification_sent = time.time()

        # queue has space for 10 messages
        self.notification_queue = collections.deque(maxlen=10)

        # default flush interval for notification thread (default to 5 seconds)
        self.flush_interval = 5

        try:
            self.mailer = Mailer(
                                 mail_host,
                                 mail_port,
                                 mail_username,
                                 mail_password,
                                 mail_sec
                                 )
        except MailerError as msg:
            self.logger.error('Error creating alerter: %s' % (msg))

        t = threading.Thread(target=self._flush_notifications)
        t.daemon = True
        t.start()

    def alert(self, ip, port, msg=None):
        # alerting functionality is rather slow because of geoip lookup and name resolution
        # notify user asynchronously in additional thread and do not wait for thread finish
        t = threading.Thread(target=self._do_alert, args=(ip, port, msg))
        t.daemon = True
        t.start()

    def _do_alert(self, ip, port, msg=None):
        for country in self.trigger_country_list:
            # check if IP belongs to currently monitored country
            match = geoip.geolite2.lookup(ip)
            if match and match.country == country:
                host = self._get_host(ip)

                # user can specify custom message
                # if no msg has been specified, send predefined message
                if msg is None:
                    msg = '%s detected attack on %s (%s) port %d @ %s' % (self.name, ip, host, port, datetime.datetime.now())
                self.notification_queue.append(msg)

    # rate limiting based on https://stackoverflow.com/questions/667508/whats-a-good-rate-limiting-algorithm#
    def _flush_notifications(self):
        while True:
            # if notification queue is not empty, flush messages with appropriate rate-limiting
            while self.notification_queue:
                now = time.time()
                time_since_last_notif = now - self.last_notification_sent
                self.notification_allowance += time_since_last_notif * (self.notification_rate / 60.0)
                if (self.notification_allowance > self.notification_rate):
                    self.notification_allowance = float(self.notification_rate)
                if (self.notification_allowance < 1.0):
                    # rate limit effect!
                    time.sleep(self.flush_interval)
                else:
                    msg = self.notification_queue.popleft()
                    self.logger.info('Sending mail notification: %s' % (msg))
                    try:
                        self.mailer.send(
                                         self.mail_from,
                                         self.mail_to_list,
                                         email_subject=self.mail_subject,
                                         email_text=msg
                                         )
                        self.last_notification_sent = time.time()
                    except Exception as msg:
                        self.logger.error('Error sending mail notification: %s' % (msg))
                self.notification_allowance -= 1.0

            # if queue is empty, just wait until msg is received
            time.sleep(self.flush_interval)

    def _get_host(self, ip):
        try:
            data = socket.gethostbyaddr(ip)
            host = repr(data[0])
            return host
        except Exception:
            # fail gracefully
            return 'UNKNOWN'


class MailerError(Exception):
    pass


class Mailer(object):
    def __init__(self, host='localhost', port=0, username=None, password=None, smtp_sec=None, timeout=5, pem_priv_key=None, pem_cert_chain=None):
        self.host = host

        # SMTP security is either None (plain-text: port 25), SSL (465) or STARTTLS (port 587)
        if smtp_sec is not None:
            smtp_sec = smtp_sec.upper()
            if smtp_sec != 'SSL' and smtp_sec != 'STARTTLS':
                raise MailerError('Unknown smtp_sec: %s - Use None, SSL or STARTTLS' % (smtp_sec))
        self.smtp_sec = smtp_sec

        if port is None:
            if smtp_sec is None:
                port = 25
            elif smtp_sec == 'SSL':
                port = 465
            elif smtp_sec == 'STARTTLS':
                port = 587

        self.port = port

        if username is None or password is None:
            raise MailerError('SMTP username and password cannot be empty!')

        self.username = username
        self.password = password
        self.timeout = timeout
        self.pem_priv_key = pem_priv_key
        self.pem_cert_chain = pem_cert_chain

    def send(self, email_from=None, email_to=[], email_cc=[], email_bcc=[], email_subject=None, email_text=None, email_raw=None, email_html=None, email_attachments=[]):
        socket_default_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self.timeout)
        try:
            if email_from is None:
                raise MailerError('Mail sender must be specified!')
            if not email_to:
                raise MailerError('Mail recepient must be specified!')
            if email_raw is None and email_subject is None:
                raise MailerError('Mail subject must be specified!')

            if self.smtp_sec is None or self.smtp_sec == 'STARTTLS':
                smtp = smtplib.SMTP(host=self.host, port=self.port, timeout=self.timeout)
            elif self.smtp_sec == 'SSL':
                smtp = smtplib.SMTP_SSL(host=self.host, port=self.port, timeout=self.timeout, keyfile=self.pem_priv_key, certfile=self.pem_cert_chain)

            smtp.ehlo_or_helo_if_needed()

            if self.smtp_sec == 'STARTTLS':
                smtp.starttls(keyfile=self.pem_priv_key, certfile=self.pem_cert_chain)
                smtp.ehlo()

            smtp.login(self.username, self.password)
            to_str = ','.join([e.strip() for e in email_to])
            cc_str = ','.join([e.strip() for e in email_cc])
            bcc_str = ','.join([e.strip() for e in email_bcc])

            if email_raw is None:
                msg = MIMEMultipart('mixed')
                msg['Subject'] = email_subject
                msg['From'] = email_from
                msg['To'] = to_str
                msg['CC'] = cc_str

                part = MIMEMultipart('alternative')

                if email_text is not None:
                    part.attach(MIMEText(email_text.encode('utf-8'), 'plain', 'utf-8'))
                if email_html is not None:
                    part.attach(MIMEText(email_html.encode('utf-8'), 'html', 'utf-8'))
                msg.attach(part)

                for attachment in email_attachments:
                    with open(attachment, 'rb') as f:
                        attachment_data = f.read()
                        part = MIMEApplication(attachment_data)
                        part.add_header('Content-Disposition', 'attachment', filename=os.path.basename(attachment))
                        msg.attach(part)

                email_raw = msg.as_string()

            smtp.sendmail(email_from, to_str + cc_str + bcc_str, email_raw)

            try:
                smtp.quit()
            except smtplib.SMTPServerDisconnected:
                # sometimes this exception happens on smtp.quit(), ignorable (probably) - the email's already been sent
                pass
        finally:
            socket.setdefaulttimeout(socket_default_timeout)
