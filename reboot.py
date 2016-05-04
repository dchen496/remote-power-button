import json
import hashlib
import getpass
import argparse
import urllib2
import os

host = 'http://soba.mit.edu'
pbkdf2_rounds = 1000000
pw_hash_len = 32

def hash_password(pw, salt=None):
    if salt is None:
        salt = os.urandom(pw_hash_len)
    h = hashlib.pbkdf2_hmac('sha256', pw, salt, pbkdf2_rounds, pw_hash_len)
    return h, salt

def print_password_hash():
    pw = getpass.getpass()
    h, salt = hash_password(pw)
    hash_hex = ', '.join([ '0x'+b.encode('hex') for b in h ])
    print 'static const char password_hash[{}] = {{ {} }};'.format(len(h), hash_hex)
    print '#define PASSWORD_SALT_HEX "{}"'.format(salt.encode('hex'))

def reboot(length):
    if length < 0 or length > 255:
        raise ValueError("Length must be between 0 and 255.")
    length_hex = "%0.2x" % length

    pw = getpass.getpass()

    challenge_json = urllib2.urlopen(urllib2.Request(host + '/challenge')).read()
    challenge_obj = json.loads(challenge_json)
    challenge = challenge_obj['challenge'].decode('hex')
    salt = challenge_obj['salt'].decode('hex')

    pw_hash, salt = hash_password(pw, salt)
    h = hashlib.sha256(pw_hash + challenge).digest()
    h_hex = h.encode('hex')

    req = urllib2.Request(host + '/reboot/' + h_hex + '/' + length_hex, '')
    resp = urllib2.urlopen(req)


def main():
    parser = argparse.ArgumentParser(description='Reboot a remote computer.')
    parser.add_argument('-p, --password-hash', help='Generate password hash.',
            dest='hash_password', action='store_true')
    parser.add_argument('-l, --length', help='Time to press power button (in seconds)',
            dest='length', type=int, default='5')
    args = parser.parse_args()
    if args.hash_password:
        print_password_hash()
    else:
        reboot(args.length)

if __name__ == '__main__':
    main()
