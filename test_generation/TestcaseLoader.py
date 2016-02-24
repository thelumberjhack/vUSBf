"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

from test_case import Testcase
import json

class testcase_loader():
    def __init__(self, object_file):
        filehandler = open(object_file, 'r')
        self.payloads = []

        loaded_payloads = json.load(filehandler)
        for p in loaded_payloads:
          self.payloads.apped(test_case.from_json(p))
        print "[*] " + str(len(self.payloads)) + " testcase in file \"" + object_file + "\""

    def get_number_of_elements(self):
        return len(self.payloads)

    def get_data_chunk(self, number_of_elements):
        if len(self.payloads) == 0:
            return None
        _tmp = self.payloads[:number_of_elements]
        self.payloads = self.payloads[number_of_elements:]
        return _tmp
