"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

import base64
import json
import os
import sys
sys.path.append(os.path.abspath('../'))
import config

def deserialize(j_obj):
  def make_fuzzing_instruction(obj):
    return Fuzzing_instruction(obj["value"], obj["field"], obj["packet_type"])
  fuzzing_instructions = map(make_fuzzing_instruction, j_obj["fuzzing_instructions"])
  return Testcase(j_obj["ID"], fuzzing_instructions, j_obj["options"])

class Testcase(object):
    def __init__(self, ID, fuzzing_instructions = [], option = {}):
        self.ID = ID
        self.list = fuzzing_instructions
        self.option = option

    def S(*x):
        if len(x) == 1 and type(x[0]) == list:
            x = x[0]
        else:
            x = list(x)
        return ListSequence(x)

    def add_testcase(self, *testcase):
        # print type(testcase[0])
        if len(testcase) == 1 and type(testcase[0]) == list:
            self.list.append(testcase[0])
        else:
            self.list.extend(testcase)

    def serialize_obj(self):
       """Serialize this class and sub classes"""
       def objectify_fuzzing_instr(fuzzing_instr):
         return {
            "value" : fuzzing_instr.value,
            "field" : fuzzing_instr.field,
            "packet_type" : fuzzing_instr.packet_type
         }

       obj =  {
         "ID" : self.ID,
         "fuzzing_instructions": map(objectify_fuzzing_instr, self.list),
         "options" : self.option
       }
       return obj

    def get_ID(self):
        return self.ID

    def get_number_of_testcases(self):
        return len(self.list)

    def get_testcase(self, num):
        try:
            return self.list[num]
        except:
            raise Exception("Bounds exception (num=" + str(num) + ")")

    def get_testcases(self):
        return self.list

    def add_option(self, key, value):
        self.option[str(key)] = str(value)

    def add_options(self, hm):
        self.option = hm

    def get_option(self, key):
        return self.option[key]

    def get_options(self):
        return self.option.keys()

    def __str__(self):
        return json.dumps(self.serialize_obj(), indent = 2)


class Instruction(object):
    def __init__(self):
        pass

    def gen_info_string(self):
        return "stub"


class Fuzzing_instruction(Testcase):
    def __init__(self, value, field, packet_type):
        self.value = value
        self.field = field
        self.packet_type = packet_type

    def gen_info_string(self):
        output = "FT: "
        try:
            output += self.value + "\t"
        except:
            output += str(self.value) + "\t"
        output += self.field + ": " + self.packet_type

        return output

    def get_value(self):
        return self.value

    def get_field(self):
        return self.field

    def get_packet_type(self):
        return self.packet_type

    def __str__(self):
        return self.gen_info_string()


if __name__ == "__main__":
    testcase = Testcase(33346)
    testcase.add_testcase(Fuzzing_instruction(1337, "A", "I"))
    testcase.add_testcase(Fuzzing_instruction("YO00", "B", "II"))
    testcase.add_testcase(Fuzzing_instruction(3317, "C", "III"))
    testcase.add_testcase(Fuzzing_instruction(12, "A", "I"), Fuzzing_instruction(21, "A", "I"))
    # print testcase.print_message()

    testcase.add_option(1, "Eins")
    testcase.add_option(2, "Zwei")
    testcase.add_option(3, "Drei")

