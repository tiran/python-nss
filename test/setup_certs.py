#!/usr/bin/python

import traceback
import getopt
import sys
import os
import errno
import logging
import subprocess
import shutil
import shlex
import pty
import tty
import re
import time

#-------------------------------------------------------------------------------

__all__ = ["config", "setup_certs"]

if __name__ == '__main__':
    prog_name = os.path.basename(sys.argv[0])
else:
    prog_name = 'setup_certs'

serial_number = 0
hostname = os.uname()[1]
client_username = 'test_user'

config = {
    'verbose'          : False,
    'debug'            : False,
    'logfile'          : 'setup_certs.log',
    'log_level'        : logging.WARN,
    'interactive'      : sys.stdout.isatty(),
    'dbdir'            : os.path.join(os.path.dirname(sys.argv[0]), 'pki'),
    'db_passwd'        : 'db_passwd',
    'noise_file'       : 'noise_file',
    'ca_subject'       : 'CN=Test CA',
    'ca_nickname'      : 'test_ca',
    'server_subject'   : 'CN=%s' % hostname,
    'server_nickname'  : 'test_server',
    'client_subject'   : 'CN=%s' % client_username,
    'client_nickname'  : client_username,
}

#-------------------------------------------------------------------------------

class CmdError(Exception):
    def __init__(self, cmd, exit_code, msg):
        self.cmd = cmd
        self.exit_code = exit_code
        self.msg = msg

    def __str__(self):
        return "Command \"%s\"\nFailed with exit code = %s\nOutput was:\n%s\n" % \
            (self.cmd, self.exit_code, self.msg)

#-------------------------------------------------------------------------------

def next_serial():
    global serial_number
    serial_number += 1
    return serial_number

def create_noise_file():
    """
    Generate a noise file to be used when creating a key
    """
    if os.path.exists(config['noise_file']):
        os.remove(config['noise_file'])

    f = open(config['noise_file'], "w")
    f.write(os.urandom(40))
    f.close()

    return

def run_cmd(cmd, input=None):
    logging.debug("running command: %s", cmd)

    if input is None:
        stdin = None
    else:
        stdin = subprocess.PIPE

    p = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate(input)
    status = p.returncode
    if config['verbose']:
        logging.debug("cmd status = %s", status)
        logging.debug("cmd stdout = %s", stdout)
        logging.debug("cmd stderr = %s", stderr)
    return status, stdout, stderr

def run_cmd_with_prompts(cmd, prompts):
    logging.debug('running command: %s', cmd)

    argv = shlex.split(cmd)

    pid, master_fd = pty.fork()
    if pid == 0:
        os.execlp(argv[0], *argv)

    time.sleep(0.1)            # FIXME: why is this necessary?
    output = ''
    search_position = 0
    cur_prompt = 0
    if cur_prompt < len(prompts):
        prompt_re = re.compile(prompts[cur_prompt][0])
        response = prompts[cur_prompt][1]
        cur_prompt += 1
    else:
        prompt_re = None
        response = None

    while True:
        try:
            new_data = os.read(master_fd, 1024)
        except OSError, e:
            if e.errno == errno.EIO: # process exited
                break
            else:
                raise
        if len(new_data) == 0:
            break               # EOF
        output += new_data
        logging.debug('output="%s"', output[search_position:]);
        if prompt_re is not None:
            logging.debug('search pattern = "%s"', prompt_re.pattern)
            match = prompt_re.search(output, search_position)
            if match:
                search_position = match.end()
                parsed = output[match.start() : match.end()]
                logging.debug('found prompt: "%s"', parsed)
                logging.debug('writing response: "%s"', response)
                os.write(master_fd, response)

                if cur_prompt < len(prompts):
                    prompt_re = re.compile(prompts[cur_prompt][0])
                    response = prompts[cur_prompt][1]
                    cur_prompt += 1
                else:
                    prompt_re = None
                    response = None


    exit_value = os.waitpid(pid, 0)[1]
    exit_signal = exit_value & 0xFF
    exit_code = exit_value >> 8
    #logging.debug('output="%s"' % output)
    logging.debug('cmd signal=%s, exit_code=%s' % (exit_signal, exit_code))

    return exit_code, output


#-------------------------------------------------------------------------------

def setup_certs():
    print 'setting up certs ...'

    if os.path.exists(config['dbdir']):
       shutil.rmtree(config['dbdir'])
    os.makedirs(config['dbdir'])

    try:

        create_noise_file()

        # 1. Create the database
        cmd = 'certutil -N -d %(dbdir)s' % config
        exit_code, output = run_cmd_with_prompts(cmd,
            [('Enter new password:\s*', config['db_passwd'] + '\n'),
             ('Re-enter password:\s*',  config['db_passwd'] + '\n')])
        if exit_code != 0:
            raise CmdError(cmd, exit_code, output)

        # 2. Create a root CA certificate
        config['serial_number'] = next_serial()
        cmd = 'certutil -S -d %(dbdir)s -z %(noise_file)s -s "%(ca_subject)s" -n "%(ca_nickname)s" -x -t "CTu,C,C" -m %(serial_number)d' % config
        exit_code, output = run_cmd_with_prompts(cmd,
            [('Enter Password or Pin for "NSS Certificate DB":\s*', config['db_passwd'] + '\n')])
        if exit_code != 0:
            raise CmdError(cmd, exit_code, output)

        # 3. Create a server certificate and sign it.
        config['serial_number'] = next_serial()
        cmd = 'certutil -S -d %(dbdir)s -z %(noise_file)s -c %(ca_nickname)s -s "%(server_subject)s" -n "%(server_nickname)s" -t "u,u,u" -m %(serial_number)d' % config
        exit_code, output = run_cmd_with_prompts(cmd,
            [('Enter Password or Pin for "NSS Certificate DB":\s*', config['db_passwd'] + '\n')])
        if exit_code != 0:
            raise CmdError(cmd, exit_code, output)

        # 4. Create a client certificate and sign it.
        config['serial_number'] = next_serial()
        cmd = 'certutil -S -d %(dbdir)s -z %(noise_file)s -c %(ca_nickname)s -s "%(client_subject)s" -n "%(client_nickname)s" -t "u,u,u" -m %(serial_number)d' % config
        exit_code, output = run_cmd_with_prompts(cmd,
                                                 [('Enter Password or Pin for "NSS Certificate DB":\s*', config['db_passwd'] + '\n')])
        if exit_code != 0:
            raise CmdError(cmd, exit_code, output)

        # 5. Import public root CA's
        cmd = 'modutil -dbdir %(dbdir)s -add ca_certs -libfile libnssckbi.so' % config
        exit_code, stdout, stderr = run_cmd(cmd)
        if exit_code != 0:
            raise CmdError(cmd, exit_code, output)

        # 6. Create a sub CA certificate
        config['serial_number'] = next_serial()
        config['subca_subject'] = 'CN=subca'
        config['subca_nickname'] = 'subca'
        cmd = 'certutil -S -d %(dbdir)s -z %(noise_file)s -c %(ca_nickname)s -s "%(subca_subject)s" -n "%(subca_nickname)s" -t "CTu,C,C" -m %(serial_number)d' % config
        exit_code, output = run_cmd_with_prompts(cmd,
            [('Enter Password or Pin for "NSS Certificate DB":\s*', config['db_passwd'] + '\n')])
        if exit_code != 0:
            raise CmdError(cmd, exit_code, output)

        # 7. Create a server certificate and sign it with the subca.
        config['serial_number'] = next_serial()
        config['server_subject'] = config['server_subject'] + "_" + config['subca_nickname']
        config['server_nickname'] = config['server_nickname'] + "_" + config['subca_nickname']
        cmd = 'certutil -S -d %(dbdir)s -z %(noise_file)s -c %(subca_nickname)s -s "%(server_subject)s" -n "%(server_nickname)s" -t "u,u,u" -m %(serial_number)d' % config
        exit_code, output = run_cmd_with_prompts(cmd,
            [('Enter Password or Pin for "NSS Certificate DB":\s*', config['db_passwd'] + '\n')])
        if exit_code != 0:
            raise CmdError(cmd, exit_code, output)

    finally:
        if os.path.exists(config['noise_file']):
            os.remove(config['noise_file'])

    logging.info('certifcate database password="%(db_passwd)s"', config)
    logging.info('CA nickname="%(ca_nickname)s", CA subject="%(ca_subject)s"', config)
    logging.info('server nickname="%(server_nickname)s", server subject="%(server_subject)s"', config)
    logging.info('client nickname="%(client_nickname)s", client subject="%(client_subject)s"', config)

#-------------------------------------------------------------------------------

class Usage(Exception):
    def __init__(self, msg):
        self.msg = msg

def usage():
    '''
    Print command help.
    '''

    return '''\
-h --help               print help
-l --log-level level    set the logging level, may be one of:
                        debug, info, warn, error, critical
-L --logfile filename   log to this file, empty string disables logging to a file
-v --verbose            be chatty
-d --debug              show run information
-w --password           set the certificate database password
-d --dbdir              set the datbase directory
-s --server-subject     set the server's subject

Examples:

%(prog_name)s -m 10
''' % {'prog_name' : prog_name,
      }

#-------------------------------------------------------------------------------

def main(argv=None):
    if argv is None:
        argv = sys.argv

    try:
        try:
            opts, args = getopt.getopt(argv[1:], 'hl:L:vDw:d:s:',
                                       ['help', 'logfile=', 'verbose', 'debug',
                                        'password', 'dbdir', 'server-subject'])
        except getopt.GetoptError, e:
            raise Usage(e)
            return 2

        for o, a in opts:
            if o in ('-h', '--help'):
                print >>sys.stdout, usage()
                return 0
            elif o in ('-L', '--logfile'):
                if not a:
                    config['logfile'] = None
                else:
                    config['logfile'] = a
            elif o in ('-l', '--log-level'):
                if a.upper() in logging._levelNames:
                    config['log_level'] = logging._levelNames[a.upper()]
                else:
                    print >>sys.stderr, "ERROR: unknown log-level '%s'" % a
            elif o in ('-v', '--verbose'):
                config['verbose'] = True
            elif o in ('-D', '--debug'):
                config['debug'] = True
            elif o in ('-w', '--password'):
                config['db_passwd'] = a
            elif o in ('-d', '--dbdir'):
                config['dbdir'] = a
            elif o in ('-s', '--server-subject'):
                config['server_subject'] = 'CN=%s' % a
            else:
                raise Usage("command argument '%s' not handled, internal error" % o)
    except Usage, e:
        print >>sys.stderr, e.msg
        print >>sys.stderr, "for help use --help"
        return 2

    if config['verbose']:
        config['log_level'] = logging.INFO
    if config['debug']:
        config['log_level'] = logging.DEBUG

    # Initialize logging
    logging.basicConfig(level=config['log_level'],
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%m-%d %H:%M',
                        filename=config['logfile'],
                        filemode='a')

    if config['interactive']:
        # Create a seperate logger for the console
        console_logger = logging.StreamHandler()
        console_logger.setLevel(config['log_level'])
        # set a format which is simpler for console use
        formatter = logging.Formatter('%(message)s')
        console_logger.setFormatter(formatter)
        # add the handler to the root logger
        logging.getLogger('').addHandler(console_logger)

    try:
        setup_certs()
    except Exception, e:
        logging.error(traceback.format_exc())
        logging.error(str(e))
        return 1

    return 0

#-------------------------------------------------------------------------------

if __name__ == '__main__':
    sys.exit(main())
