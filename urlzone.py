# Dennis Schwarz, Arbor Networks ASERT, June 2015

import time
import random
import struct
import tempfile
import os
import subprocess
import re
import xxtea
import zlib
import sys

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import AES


class UrlZone:
    def __init__(self, url, botid, botshid, rsa_key_pem, tver, xxtea_key):
        self.url = url
        self.botid = botid
        self.botshid = botshid
        self.rsa_key_pem = rsa_key_pem
        self.tver = tver
        self.xxtea_key = xxtea_key


    def gen_prepend(self, cmd):
        # '23EAFB108B80B7E06E3A111000111\x00\x00\x00\x00\x006.10200\xc88ZTExplorer 6.1.7601.17514\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        # 81 bytes
        buf = []

        buf.append(cmd)
        buf.append(self.botid)
        buf.append(self.botshid)

        # padding
        buf.append("\x00"*(34-len("".join(buf))))

        # MajorVersion.MinorVersion
        buf.append("6.1")

        # can be 0 or 1 depending on registry key
        buf.append("0")

        buf.append("0")

        buf.append("0")

        buf.append("1")

        # unix timestamp
        buf.append(struct.pack("I", int(time.time())))

        # file version info
        buf.append("Explorer 6.1.7601.17514")

        # padding
        buf.append("\x00"*(81-len("".join(buf))))

        return "".join(buf)


    def encrypt_prepend(self, prepend, query_str_len):
        buf = []

        # 2 AES keys generated at run time, 16 bytes each
        aes_encrypt_key = "".join([chr(random.getrandbits(8)) for i in range(16)])
        aes_decrypt_key = "".join([chr(random.getrandbits(8)) for i in range(16)])
        buf.append(aes_encrypt_key)
        buf.append(aes_decrypt_key)

        # query str len
        size_field = struct.pack("I", query_str_len)
        buf.append(size_field)

        buf.append(prepend)

        rsa_key = RSA.importKey(self.rsa_key_pem)
        rsa = PKCS1_v1_5.new(rsa_key)

        enc_prepend = rsa.encrypt("".join(buf))

        keys = {
            "enc": aes_encrypt_key,
            "dec": aes_decrypt_key
        }

        return enc_prepend, keys


    def gen_query_str(self, vcmd, cc, hh, ipcnf, sckport, pros, keret, email):
        # '?tver=1386809672&vcmd=0&cc=24&hh=0F857102&ipcnf=10.0.2.15+&sckport=0&pros=0&keret=04090409;&email='
        query_str = "?tver=%s&vcmd=%s&cc=%s&hh=%s&ipcnf=%s&sckport=%s&pros=%s&keret=%s&email=%s" % \
            (self.tver, vcmd, cc, hh, ipcnf, sckport, pros, keret, email)

        return query_str


    def encrypt_query_str(self, aes_key, query_str):
        aes = AES.new(aes_key, AES.MODE_ECB)

        buf = struct.pack("I", len(query_str)) + query_str

        # padding
        if len(buf) % 16 != 0:
            x = len(buf) / 16
            x += 1
            padding_size = (x * 16) - len(buf)
            padding = "".join([chr(random.getrandbits(8)) for i in range(padding_size)])
        else:
            padding = ""

        buf += padding

        enc_query_str = aes.encrypt(buf)

        return enc_query_str


    def phonehome(self):
        # "2" is the "phonehome" command
        prepend = self.gen_prepend("2")

        ipcnf = "10.0.%d.%d+" % (random.randint(1, 255), random.randint(1, 255))
        query_str = self.gen_query_str("0", "0", "0", ipcnf, "0", "0", "04090409;", "")

        enc_prepend, aes_keys = self.encrypt_prepend(prepend, len(query_str))

        enc_query_str = self.encrypt_query_str(aes_keys["enc"], query_str)

        post_data = enc_prepend + enc_query_str

        # XXX
        # because urllib2 and requests force headers that urlzone doesn't like
        # i'm looking at your Accept-Encoding: identity
        fp, path = tempfile.mkstemp()
        os.write(fp, post_data)
        os.close(fp)

        curl_cmd = "curl -m 300 -k -X POST -A 'Microsoft-CryptoAPI/6.1' -H 'Accept:' --header 'Content-Type:' -H 'Cache-Control: no-cache' --data-binary @%s %s" % (path, url)
        shell = subprocess.Popen(curl_cmd, stdout=subprocess.PIPE, shell=True)

        shell_response = shell.communicate()[0]

        if not shell_response:
            return

        try:
            aes = AES.new(aes_keys["dec"], AES.MODE_ECB)
            command = aes.decrypt(shell_response)
        except:
            print "bad aes decrypt"
            return

        return command


    def parse_command(self, command):
        if "CMD0" in command:
            print "sleep command (CMD0) from %s" % self.url

        elif "INJECTFILE" in command:
            print "config command (INJECTFILE) from %s" % self.url

            match = re.search(">CV [0-9]+\r\n>DI\r\nINJECTFILE (?P<config_size>[0-9]+)\r\n", command)
            if not match:
                print "unhandled INJECTFILE command: %s" % command[0:64]
                return

            enc = command[match.end():match.end()+int(match.groupdict()["config_size"])]

            config = None
            try:
                comp = xxtea.decrypt(enc, self.xxtea_key, False)
                config = zlib.decompress(comp[10:], -15)
            except:
                print "bad decrypt or decompress"
                return

            if config:
                print "written to INJECTFILE (%d bytes)" % len(config)
                fp = open("INJECTFILE", "wb")
                fp.write(config)
                fp.close()

        elif "EXEUPDATE" in command:
            print "update command (EXEUPDATE) from %s" % self.url

            match = re.search(">CV CMP\r\n>UD [0-9]+\r\n\*EXEUPDATE (?P<file_size>[0-9]+)\r\n", command)
            if not match:
                print "unhandled EXEUPDATE command: %s" % command[0:64]
                return

            update = command[match.end():match.end()+int(match.groupdict()["file_size"])]
            if update:
                print "written to EXEUPDATE (%d bytes)" % len(update)
                fp = open("EXEUPDATE", "wb")
                fp.write(update)
                fp.close()

        else:
            print "unknown command from %s: %s" % (self.url, command[0:64])
        

if __name__ == "__main__":
    # one of the DGA URLs
    #url = "https://anptlnadkpkhmc3.net/gnu/"
    url = "change.me.to.a.real.c2"

    # probably can be randomly generated
    botid = "35F368C84B596D17F9"

    # should be extracted from memdump
    botshid = "Y010000001"

    # should be extracted from memedump
    # PUBLICKEYBLOB, 148 bytes
    rsa_key_blob = "0602000000a40000525341310004000001000100757c626e1d05d7e5a89b62eacf2e1c45e7e5f33644f7372c0040d91fd9d937337e2adb7f331da68942594efa0fb302b13e2d8999daaf4f98890fdb45f7e2878eabce23aad62f5ea6304f2d159f1458c662bb872b80ea6a02d3e91a63fc9dc1a375655d94219dca7f4e5711d4084c07a93779bfed3df6c5332bcd1dea226fe7d5".decode("hex")
    fp, path = tempfile.mkstemp()
    os.write(fp, rsa_key_blob)
    os.close(fp)

    pem_path = "%s.pem" % path
    openssl_cmd = "openssl rsa -pubin -inform MS\ PUBLICKEYBLOB -in %s -outform PEM -out %s" % (path, pem_path)
    subprocess.call(openssl_cmd, shell=True)

    fp = open(pem_path, "rb")
    rsa_key_pem = fp.read()
    fp.close()

    # should be extracted from memdump
    # unix timestamp
    tver = "1434110463" # INJECTFILE
    #tver = "1433290738" # EXEUPDATE

    # should be extracted from memdump
    xxtea_key = "7fe4746e80761a9285d4a63b9e3e0704".decode("hex")

    urlzone = UrlZone(url, botid, botshid, rsa_key_pem, tver, xxtea_key)
    
    command = urlzone.phonehome()
    if not command:
        print "couldn't get command from %s" % url
        sys.exit(1)

    urlzone.parse_command(command)
