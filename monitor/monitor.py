"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

import sys
import os
sys.path.append(os.path.abspath('../'))
import config


class Monitor(object):
    def __init__(self, qemu, filename):
        if not qemu:
            raise Exception("qemu null pointer")
        self.qemu = qemu
        if not filename:
            raise Exception("filename null pointer")
        self.filename = filename

    def log_reload(self):
        if self.filename != "":
            with open(self.filename, "a") as log_file:
                log_file.write(config.MESSAGE_VM_RELOAD)

    def monitor(self, title):
        pass
