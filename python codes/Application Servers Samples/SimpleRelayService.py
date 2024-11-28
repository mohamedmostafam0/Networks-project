
import os
import re
import daemon
import asyncore
import smtpd

class SimpleRelayService(smtpd.PureProxy):
    """Handles processing mail for relay"""

    def __init__(self, config, bind, remote):
        smtpd.SMTPServer.__init__(self, bind, remote)
        self.config = config
        import logging
        logging.basicConfig(filename=config['log_file'],
                            level=logging.DEBUG,
                            format="%(asctime)s %(levelname)s %(message)s")
        logging.info("Simple relay service started on %s:%s" % bind)

    def process_message(self, peer, mailfrom, rcpttos, data):
        logging.debug("Receieved a message from %s to %s" % (mailfrom, rcpttos))
        refused = self._deliver(mailfrom, rcpttos, data)

if __name__ == "__main__":

    log_file = 'simplerelay.log'
    if os.environ.has_key('LOG_FILE'):
        log_file = os.environ['LOG_FILE']

    bind = (os.environ['BIND_ADDRESS'], int(os.environ['BIND_PORT']))
    relay = (os.environ['RELAY_HOST'], int(os.environ['RELAY_HOST_PORT']))
    config = {
        'log_file': log_file,
        'rcpt_domain': '',
        'fwd_address': ''}

    if os.environ.has_key('DAEMONIZE') and bool(os.environ['DAEMONIZE']):
        from daemon.pidlockfile import PIDLockFile
        pidfile = PIDLockFile(os.environ['PIDFILE'])
        working_directory = os.environ['WORKING_DIRECTORY']
        startup_log_file=open(log_file, 'a')
        with daemon.DaemonContext(pidfile=pidfile, working_directory=working_directory,
                                  stdout=startup_log_file, stderr=startup_log_file):
            smtp_server = SimpleRelayService(config, bind, relay)
            asyncore.loop()
    else:
        smtp_server = SimpleRelayService(config, bind, relay)
        try:
            asyncore.loop()
        except KeyboardInterrupt:
            smtp_server.close()