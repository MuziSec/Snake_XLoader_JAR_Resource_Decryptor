from hashlib import sha1
from Crypto.Cipher import AES
from binascii import hexlify, unhexlify
from pyunpack import Archive
from argparse import ArgumentParser
import os
import subprocess
import re
from shutil import copyfile
from shutil import rmtree

def decompile_class_file(path):
    for d in os.listdir(path):
        if d in ['resources', 'META-INF']:
            continue
        else:
            new_path = f'{path}/{d}'
            for f in os.listdir(f'{path}/{d}'):
                try:
                    subprocess.call(['java', '-jar', 'cfr.jar', f'{path}/{d}/{f}', '--outputdir', f'{path}/'])
                except Exception as e:
                    print(f'There was a problem calling cfr to decompile: {e}')

    return new_path

def extract_payloads(path, outputdir):
    filename = path.split('/')[-1].split('.')[0]
    dir_path = f'./tmp/{filename}'
    os.makedirs(dir_path, exist_ok=True)
    Archive(path).extractall(dir_path)
    new_path = decompile_class_file(dir_path)
    for f in os.listdir(new_path):
        if f.split('.')[0] == 'AES' or f.split('.')[-1] == 'class':
            continue
        else:
            copyfile(f'{new_path}/{f}', f'{outputdir}/{f}')
            # Find where getSHA1 occurs
            with open(f'{new_path}/{f}', 'r') as fp:
                code = fp.read()
                f_call = re.search("\.getSHA1\(\w+\.", code)
                key_var = f_call[0].split('(')[1].split('.')[0]
                key_str = re.search(rf"String\s+{key_var}\s+=\s+\"\w+\";", code)
                key = re.sub(r'\W+', '', key_str[0].split()[-1])
                key = sha1(key.encode('utf-8')).hexdigest()[:16].encode('utf-8')
    decrypt_files(key, dir_path, outputdir)
    cleanup()

def decrypt_files(key, path, outputdir):
    for f in os.listdir(path):
        if f.lower() == 'resources':
            for g in os.listdir(f'{path}/{f}'):
                with open(f'{path}/{f}/{g}', 'rb') as fp:
                    data = fp.read()
                    decryptor = AES.new(key, AES.MODE_ECB)

                    with open(f'{outputdir}/{g}', 'wb') as outfile:
                        outfile.write(decryptor.decrypt(data))

def cleanup():
    rmtree('./tmp/')

def parse_args():
    usage = "java_dropper_extractor.py [OPTION]... [FILES]..."
    parser = ArgumentParser(description=usage)
    parser.add_argument('-o', '--outputdir', help='Directory to output extracted payload to', default=None)
    parser.add_argument('files', nargs='+')
    return parser.parse_args()


def main():
    args = parse_args()
    if args.outputdir:
        os.makedirs(args.outputdir, exist_ok=True)
        outputdir = args.outputdir
    else:
        os.makedirs('output', exist_ok=True)
        outputdir = 'output'
    for path in args.files:
        extract_payloads(path, outputdir)

if __name__ == "__main__":
    main()

