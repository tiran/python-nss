#!/usr/bin/python

import argparse
import atexit
import logging
import os
import shutil
import subprocess
import sys
from string import Template
import tempfile

#-------------------------------------------------------------------------------

class CmdError(Exception):
    def __init__(self, exit_status, message, stderr=None):
        self.exit_status = exit_status
        self.message = message
        self.stderr = stderr

    def __str__(self):
        return self.message


def exit_handler(options):
    logging.debug('in exit handler')

    if options.passwd_filename is not None:
        logging.debug('removing passwd_filename=%s', options.passwd_filename)
        os.remove(options.passwd_filename)

    if options.noise_filename is not None:
        logging.debug('removing noise_filename=%s', options.noise_filename)
        os.remove(options.noise_filename)

def write_serial(options, serial_number):
    with open(options.serial_file, 'w') as f:
        f.write('%x\n' % serial_number)


def read_serial(options):
    if not os.path.exists(options.serial_file):
        write_serial(options, options.serial_number)

    with open(options.serial_file) as f:
        serial_number = int(f.readline(), 16)
    return serial_number


def init_noise_file(options):
    '''Generate a noise file to be used when creating a key

    We create a temporary file on first use and continue to use
    the same temporary file for the duration of this process.
    Each time this function is called it writes new random data
    into the file.
    '''
    random_data = os.urandom(40)

    if options.noise_filename is None:
        fd, options.noise_filename = tempfile.mkstemp()
        os.write(fd, random_data)
        os.close(fd)
    else:
        with open(options.noise_filename, 'w') as f:
            f.write(random_data)
    return

def create_passwd_file(options):
    fd, options.passwd_filename = tempfile.mkstemp()
    os.write(fd, options.db_passwd)
    os.close(fd)


def format_cert(options, nickname):
    cmd_args = ['/usr/bin/certutil',
                '-L',                          # OPERATION: list
                '-d', options.db_name,         # NSS database
                '-f', options.passwd_filename, # database password in file
                '-n', nickname,                # nickname of cert to list
                ]


    logging.debug(' '.join(cmd_args))
    p = subprocess.Popen(cmd_args,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    exit_status = p.returncode
    if exit_status != 0:
        raise CmdError(exit_status,
                       'failed to list cert nickname "%s"' % (nickname),
                       stderr)
    return stdout

#-------------------------------------------------------------------------------

def create_database(options):
    if os.path.exists(options.db_dir) and not os.path.isdir(options.db_dir):
        raise ValueError('db_dir "%s" exists but is not a directory' % options.db_dir)

    # Create resources
    create_passwd_file(options)

    if options.clean:
        logging.info('Creating clean database directory: "%s"', options.db_dir)
        if os.path.exists(options.db_dir):
            shutil.rmtree(options.db_dir)
        os.makedirs(options.db_dir)

        cmd_args = ['/usr/bin/certutil',
                    '-N',                          # OPERATION: create database
                    '-d', options.db_name,         # NSS database
                    '-f', options.passwd_filename, # database password in file
                    ]

        logging.debug(' '.join(cmd_args))
        p = subprocess.Popen(cmd_args,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        exit_status = p.returncode
        if exit_status != 0:
            raise CmdError(exit_status,
                           'failed to create NSS database "%s"' % (options.db_name),
                           stderr)
    else:
        logging.info('Using existing database directory: "%s"', options.db_dir)

def create_ca_cert(options):
    serial_number = read_serial(options)
    init_noise_file(options)

    logging.info('creating ca cert: subject="%s", nickname="%s"',
                 options.ca_subject, options.ca_nickname)

    cmd_args = ['/usr/bin/certutil',
                '-S',                            # OPERATION: create signed cert
                '-x',                            # self-sign the cert
                '-d', options.db_name,           # NSS database
                '-f', options.passwd_filename,   # database password in file
                '-n', options.ca_nickname,       # nickname of cert being created
                '-s', options.ca_subject,        # subject of cert being created
                '-g', str(options.key_size),     # keysize
                '-t', 'CT,,CT',                  # trust
                '-1',                            # add key usage extension
                '-2',                            # add basic contraints extension
                '-5',                            # add certificate type extension
                '-m', str(serial_number),        # cert serial number
                '-v', str(options.valid_months), # validity in months
                '-z', options.noise_filename,    # noise file random seed
                ]

    logging.debug(' '.join(cmd_args))
    p = subprocess.Popen(cmd_args,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)

    # Provide input for extension creation prompting
    input = ''

    # >> Key Usage extension <<
    # 0 - Digital Signature
    # 1 - Non-repudiation
    # 2 - Key encipherment
    # 3 - Data encipherment
    # 4 - Key agreement
    # 5 - Cert signing key
    # 6 - CRL signing key
    # Other to finish
    input += '0\n1\n5\n100\n'
    # Is this a critical extension [y/N]?
    input += 'y\n'

    # >> Basic Constraints extension <<
    # Is this a CA certificate [y/N]?
    input += 'y\n'
    # Enter the path length constraint, enter to skip [<0 for unlimited path]: > 2
    input += '%d\n' % options.ca_path_len
    # Is this a critical extension [y/N]?
    input += 'y\n'

    # >> NS Cert Type extension <<
    # 0 - SSL Client
    # 1 - SSL Server
    # 2 - S/MIME
    # 3 - Object Signing
    # 4 - Reserved for future use
    # 5 - SSL CA
    # 6 - S/MIME CA
    # 7 - Object Signing CA
    # Other to finish
    input += '5\n6\n7\n100\n'
    # Is this a critical extension [y/N]?
    input += 'n\n'

    stdout, stderr = p.communicate(input)
    exit_status = p.returncode
    if exit_status != 0:
        raise CmdError(exit_status,
                       'failed to create CA cert "%s"' % (options.ca_nickname),
                       stderr)

    write_serial(options, serial_number + 1)

    return options.ca_nickname

def create_server_cert(options):
    serial_number = read_serial(options)
    init_noise_file(options)

    logging.info('creating server cert: subject="%s", nickname="%s"',
                 options.server_subject, options.server_nickname)

    cmd_args = ['/usr/bin/certutil',
                '-S',                            # OPERATION: create signed cert
                '-d', options.db_name,           # NSS database
                '-f', options.passwd_filename,   # database password in file
                '-c', options.ca_nickname,       # nickname of CA used to sign this cert
                '-n', options.server_nickname,   # nickname of cert being created
                '-s', options.server_subject,    # subject of cert being created
                '-g', str(options.key_size),     # keysize
                '-t', 'u,u,u',                   # trust
                '-5',                            # add certificate type extensionn
                '-m', str(serial_number),        # cert serial number
                '-v', str(options.valid_months), # validity in months
                '-z', options.noise_filename,    # noise file random seed
                ]

    logging.debug(' '.join(cmd_args))
    p = subprocess.Popen(cmd_args,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    # Provide input for extension creation prompting
    input = ''

    # >> NS Cert Type extension <<
    # 0 - SSL Client
    # 1 - SSL Server
    # 2 - S/MIME
    # 3 - Object Signing
    # 4 - Reserved for future use
    # 5 - SSL CA
    # 6 - S/MIME CA
    # 7 - Object Signing CA
    # Other to finish
    input += '1\n100\n'
    # Is this a critical extension [y/N]?
    input += 'n\n'

    stdout, stderr = p.communicate(input)
    exit_status = p.returncode
    if exit_status != 0:
        raise CmdError(exit_status,
                       'failed to create server cert "%s"' % (options.server_nickname),
                       stderr)

    write_serial(options, serial_number + 1)

    return options.server_nickname

def create_client_cert(options):
    serial_number = read_serial(options)
    init_noise_file(options)

    logging.info('creating client cert: subject="%s", nickname="%s"',
                 options.client_subject, options.client_nickname)

    cmd_args = ['/usr/bin/certutil',
                '-S',                            # OPERATION: create signed cert
                '-d', options.db_name,           # NSS database
                '-f', options.passwd_filename,   # database password in file
                '-c', options.ca_nickname,       # nickname of CA used to sign this cert
                '-n', options.client_nickname,   # nickname of cert being created
                '-s', options.client_subject,    # subject of cert being created
                '-g', str(options.key_size),     # keysize
                '-t', 'u,u,u',                   # trust
                '-5',                            # add certificate type extensionn
                '-m', str(serial_number),        # cert serial number
                '-v', str(options.valid_months), # validity in months
                '-z', options.noise_filename,    # noise file random seed
                ]

    cmd_args = ['/usr/bin/certutil',
                '-d', options.db_name,
                '-S',
                '-c', options.ca_nickname,
                '-n', options.client_nickname,
                '-s', options.client_subject,
                '-g', str(options.key_size),
                '-t', ',,',
                '-5',
                '-m', str(serial_number),
                '-v', str(options.valid_months),
                '-z', options.noise_filename,
                '-f', options.passwd_filename,
                ]

    logging.debug(' '.join(cmd_args))
    p = subprocess.Popen(cmd_args,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)

    # Provide input for extension creation prompting
    input = ''

    # >> NS Cert Type extension <<
    # 0 - SSL Client
    # 1 - SSL Server
    # 2 - S/MIME
    # 3 - Object Signing
    # 4 - Reserved for future use
    # 5 - SSL CA
    # 6 - S/MIME CA
    # 7 - Object Signing CA
    # Other to finish
    input += '0\n100\n'
    # Is this a critical extension [y/N]?
    input += 'n\n'

    stdout, stderr = p.communicate(input)
    exit_status = p.returncode
    if exit_status != 0:
        raise CmdError(exit_status,
                       'failed to create client cert "%s"' % (options.client_nickname),
                       stderr)

    write_serial(options, serial_number + 1)

    return options.client_nickname

def add_trusted_certs(options):
    name = 'ca_certs'
    module = 'libnssckbi.so'
    logging.info('adding system trusted certs: name="%s" module="%s"',
                 name, module)

    cmd_args = ['/usr/bin/modutil',
                '-dbdir', options.db_name, # NSS database
                '-add', name,              # module name
                '-libfile', module,        # module
                ]

    logging.debug(' '.join(cmd_args))
    p = subprocess.Popen(cmd_args,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)

    input = None

    stdout, stderr = p.communicate(input)
    exit_status = p.returncode
    if exit_status != 0:
        raise CmdError(exit_status,
                       'failed to add module "%s" "%s"' % (name, module),
                       stderr)

    return name

#-------------------------------------------------------------------------------

def setup_certs(args):

    # --- cmd ---
    parser = argparse.ArgumentParser(description='create certs for testing',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('--verbose', action='store_true',
                        help='provide info level messages')

    parser.add_argument('--debug', action='store_true',
                        help='provide debug level messages')

    parser.add_argument('--quiet', action='store_true',
                        help='do not display any messages')

    parser.add_argument('--show-certs', action='store_true',
                        help='show the certificate details')

    parser.add_argument('--no-clean', action='store_false', dest='clean',
                        help='do not remove existing db_dir')

    parser.add_argument('--no-trusted-certs', dest='add_trusted_certs', action='store_false',
                        help='do not add trusted certs')

    parser.add_argument('--hostname',
                        help='hostname used in cert subjects')

    parser.add_argument('--db-type',
                        choices=['sql', ''],
                        help='NSS database type')

    parser.add_argument('--db-dir',
                        help='NSS database directory')

    parser.add_argument('--db-passwd',
                        help='NSS database password')

    parser.add_argument('--ca-subject',
                        help='CA certificate subject')

    parser.add_argument('--ca-nickname',
                        help='CA certificate nickname')

    parser.add_argument('--server-subject',
                        help='server certificate subject')

    parser.add_argument('--server-nickname',
                        help='server certificate nickname')

    parser.add_argument('--client-username',
                        help='client user name, used in client cert subject')

    parser.add_argument('--client-subject',
                        help='client certificate subject')

    parser.add_argument('--client-nickname',
                        help='client certificate nickname')

    parser.add_argument('--serial-number', type=int,
                        help='starting serial number for certificates')

    parser.add_argument('--valid-months', dest='valid_months', type=int,
                        help='validity period in months')
    parser.add_argument('--path-len', dest='ca_path_len', type=int,
                        help='basic constraints path length')
    parser.add_argument('--key-type', dest='key_type',
                        help='key type, either rsa or dsa')
    parser.add_argument('--key-size', dest='key_size',
                        help='number of bits in key (must be multiple of 8)')
    parser.add_argument('--serial-file', dest='serial_file',
                        help='name of file used to track next serial number')

    parser.set_defaults(verbose = False,
                        debug = False,
                        quiet = False,
                        show_certs = False,
                        clean = True,
                        add_trusted_certs = True,
                        hostname = os.uname()[1],
                        db_type = 'sql',
                        db_dir = 'pki',
                        db_passwd = 'db_passwd',
                        ca_subject = 'CN=Test CA',
                        ca_nickname = 'test_ca',
                        server_subject =  'CN=${hostname}',
                        server_nickname = 'test_server',
                        client_username = 'test_user',
                        client_subject = 'CN=${client_username}',
                        client_nickname = '${client_username}',
                        serial_number = 1,
                        key_type = 'rsa',
                        key_size = 1024,
                        valid_months = 12,
                        ca_path_len = 2,
                        serial_file = '${db_dir}/serial',
                        )


    options = parser.parse_args(args)

    # Do substitutions on option values.
    # This is ugly because argparse does not expose an API which permits iterating over
    # the contents of options nor a way to get the options as a dict, ugh :-(
    # So we access options.__dict__ directly.
    for key in options.__dict__.keys():
        # Assume options never begin with underscore
        if key.startswith('_'):
            continue
        value = getattr(options, key)
        # Can't substitue on non-string values
        if not isinstance(value, basestring):
            continue
        # Don't bother trying to substitute if $ substitution character isn't present
        if '$' not in value:
            continue
        setattr(options, key, Template(value).substitute(options.__dict__))

    # Set up logging
    log_level = logging.INFO
    if options.quiet:
        log_level = logging.ERROR
    if options.verbose:
        log_level = logging.INFO
    if options.debug:
        log_level = logging.DEBUG

    # Initialize logging
    logging.basicConfig(level=log_level, format='%(levelname)s: %(message)s')
    logger = logging.getLogger()

    # Synthesize some useful options derived from specified options
    if options.db_type == '':
        options.db_name = options.db_dir
    else:
        options.db_name = '%s:%s' % (options.db_type, options.db_dir)
    options.passwd_filename = None
    options.noise_filename = None

    # Set function to clean up on exit, bind fuction with options
    def exit_handler_with_options():
        exit_handler(options)
    atexit.register(exit_handler_with_options)

    cert_nicknames = []

    try:
        create_database(options)
        cert_nicknames.append(create_ca_cert(options))
        cert_nicknames.append(create_server_cert(options))
        cert_nicknames.append(create_client_cert(options))
        if options.add_trusted_certs:
            add_trusted_certs(options)
    except CmdError as e:
        logging.error(e.message)
        logging.error(e.stderr)
        return 1

    if options.show_certs:
        if logger.getEffectiveLevel() > logging.INFO:
            logger.setLevel(logging.INFO)
        for nickname in cert_nicknames:
            logging.info('Certificate nickname "%s"\n%s',
                         nickname, format_cert(options, nickname))

    logging.info('---------- Summary ----------')
    logging.info('NSS database name="%s", password="%s"',
                 options.db_name, options.db_passwd)
    logging.info('CA nickname="%s", CA subject="%s"',
                 options.ca_nickname, options.ca_subject)
    logging.info('server nickname="%s", server subject="%s"',
                 options.server_nickname, options.server_subject)
    logging.info('client nickname="%s", client subject="%s"',
                 options.client_nickname, options.client_subject)

    return 0

#-------------------------------------------------------------------------------

def main():
    return setup_certs(None)

if __name__ == '__main__':
    sys.exit(main())
