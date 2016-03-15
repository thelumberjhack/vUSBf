"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

import config
from emulator.enumeration import enumeration
from emulator.enumeration_abortion import abortion_enumeration
from emulator.hid import hid
from fuzzer import fuzzer
from lsusb_description_parser import LinuxLSUSBDescriptionParser
from usbparser import *


class USBEmulator(object):
    port = 0
    ip = ""
    unix_socket = ""

    # payload specific member variables
    payload = []
    hello_packet = ""
    connect_packet = None
    if_info_packet = None
    ep_info_packet = None
    enum_emulator = None

    # address_type:
    # 0:	[IP, TCP]
    # 1:	[Unix-Socket]
    def __init__(self, victim_address, address_type):

        if victim_address is None or address_type is None:
            raise Exception("Victim address errror")

        if address_type == 0:
            if len(victim_address) != 2:
                raise Exception("Victim address error - expected format is [IP, PORT]")
            else:
                if victim_address[0] is None or victim_address[1] is None:
                    raise Exception("Victim address error - expected format is [IP, PORT]")
            self.ip = victim_address[0]
            self.port = victim_address[1]

        elif address_type == 1:
            self.unix_socket = victim_address
        else:
            raise Exception("Unknown address type")

        self.hello_packet = config.USB_REDIR_HELLO_PACKET

    def setup_payload(self, payload):

        data = LinuxLSUSBDescriptionParser(config.DEV_DESC_FOLDER + payload.get_option("descriptor")).parse()

        self.payload = data[0]
        self.if_info_packet = data[3]
        self.ep_info_packet = data[4]
        self.connect_packet = data[2]

        fuzzer_obj = fuzzer(payload)
        fuzzer_obj.set_descriptor(self.payload)

        emulator = payload.get_option("emulator")
        if emulator == "enumeration":
            self.enum_emulator = enumeration(fuzzer_obj)
        elif emulator == "enumeration_abortion":
            self.enum_emulator = abortion_enumeration(fuzzer_obj)
        elif emulator == "hid":
            self.enum_emulator = hid(fuzzer_obj)
        else:
            raise Exception("Unknown emulator")

    def execute(self):
        connection_to_victim = self.__connect_to_server()
        if connection_to_victim is None:
            print "Unable to connect to victim..."
            return False
        r_value = self.__connection_loop(connection_to_victim)
        return r_value

    def __get_hello_packet(self):
        pkt = usbredirheader()
        pkt.Htype = 0
        pkt.HLength = 68
        pkt.Hid = 0
        pkt = pkt / Raw(self.hello_packet)
        return str(pkt)

    def __get_connect_packet(self):
        pkt = usbredirheader()
        pkt.Htype = 1
        pkt.HLength = 10
        pkt.Hid = 0
        pkt = pkt / Raw(str(self.connect_packet))
        return str(pkt)

    def __get_if_info_packet(self):
        pkt = usbredirheader()
        pkt.Htype = 4
        pkt.HLength = 132
        pkt.Hid = 0
        pkt = pkt / Raw(str(self.if_info_packet))
        return str(pkt)

    def __get_ep_info_packet(self):
        pkt = usbredirheader()
        pkt.Htype = 5
        pkt.HLength = 160
        pkt.Hid = 0
        pkt = pkt / Raw(str(self.ep_info_packet))
        return str(pkt)

    @staticmethod
    def __get_reset_packet():
        pkt = usbredirheader()
        pkt.Htype = 3
        pkt.HLength = 0
        pkt.Hid = 0
        return str(pkt)

    def __connection_loop(self, connection_to_victim):

        connection_to_victim.settimeout(config.CONNECTION_TO_VICTIM_TIMEOUT)
        try:
            # Receive the hello packet from the emulator
            hello_packet = self.__recv_data(80, connection_to_victim)
            self.__print_data(hello_packet, True)
            self.__print_data(self.__send_data(self.__get_hello_packet(), connection_to_victim), False)
            self.__print_data(self.__send_data(self.__get_if_info_packet(), connection_to_victim), False)
            self.__print_data(self.__send_data(self.__get_ep_info_packet(), connection_to_victim), False)
            self.__print_data(self.__send_data(self.__get_connect_packet(), connection_to_victim), False)
        except Exception as e:
            print "IN connection loop"
            print e
            return False

        for _ in range(config.MAX_PACKETS):
            try:
                received_data = self.__recv_data(12, connection_to_victim)
                new_packet = usbredirheader(received_data)
                if new_packet.Htype == -1:
                    return True
                raw_data = self.__recv_data_dont_print(new_packet.HLength, connection_to_victim)
                raw_data = str(new_packet) + raw_data
                new_packet = usbredir_parser(raw_data).getScapyPacket()
            except Exception as e:
                print "In looper"
                import sys, traceback
                traceback.print_exc()
                print e
                return True

            # hello packet
            if new_packet.Htype == 0:
                self.__print_data(str(new_packet), True)
                self.__print_data(self.__send_data(str(new_packet), connection_to_victim), False)

            # reset packet
            elif new_packet.Htype == 3:
                self.__print_data(str(new_packet), True)
                self.__print_data(self.__send_data(self.__get_reset_packet(), connection_to_victim), False)

            # set_configuration packet
            elif new_packet.Htype == 6:
                self.__print_data(str(new_packet), True)
                new_packet.Htype = 8
                new_packet.HLength = new_packet.HLength + 1
                new_packet.payload = Raw('\x00' + str(new_packet.payload))
                self.__print_data(self.__send_data(str(new_packet), connection_to_victim), False)
                # connection_to_victim.settimeout(0.5)

            # start_interrupt_receiving packet
            elif new_packet.Htype == 15:
                self.__print_data(str(new_packet), True)
                new_packet.Htype = 17
                new_packet.HLength = new_packet.HLength + 1
                new_packet.payload = Raw('\x00' + str(new_packet.payload))
                self.__print_data(self.__send_data(str(new_packet), connection_to_victim), False)
                return True

            # cancel_data_packet packet
            elif new_packet.Htype == 21:
                return True

            # data_control_packet packet
            elif new_packet.Htype == 100:
                # recv request
                self.__print_data(raw_data, True)
                # send response
                response = str(self.enum_emulator.get_response(str(new_packet)))
                self.__print_data(self.__send_data(response, connection_to_victim), False)

            # data_bulk_packet packet
            elif new_packet.Htype == 101:
                self.__send_data(response, connection_to_victim)

            # data_interrupt_packet packet
            elif new_packet.Htype == 103:
                new_packet.HLength = 4
                Raw(raw_data).show()
                interrupt_payload = data_interrupt_redir_header(raw_data[12:])
                Raw(str(new_packet) + str(interrupt_payload)).show()
                interrupt_payload.status = 0
                interrupt_payload.load = None
                Raw(str(new_packet) + str(interrupt_payload)).show()
                self.__send_data(str(new_packet) + str(interrupt_payload), connection_to_victim)

            else:
                return True

        return True

    @staticmethod
    def __print_data(data, recv):
        if config.VERBOSE_LEVEL >= config.VERBOSE_LEVEL_PRINT_RECV_DATA:
            print config.DELIMITER
            if recv:
                print "RECV: Type ",
            else:
                print "SEND: Type ",

            try:
                print usbredir_type_enum[usbredirheader(data).Htype]
            except:
                print usbredirheader(data).Htype
            try:
                usbredirheader(data).show()
            except:
                Raw(data).show()
            print ""

    @staticmethod
    def __recv_data(length, connection_to_victim):
        try:
            data = connection_to_victim.recv(length)
            if len(data) != length:
                print "We received an amount of data we didn't expect"
            return data
        except Exception as e:
            print e.message + " during receiving data"
            return ""

    @staticmethod
    def __recv_data_dont_print(length, connection_to_victim):
        return connection_to_victim.recv(length)

    @staticmethod
    def __send_data(data, connection_to_victim):
        try:
            bytes_sent = connection_to_victim.send(data)
            if bytes_sent != len(data):
                print("We wanted to send %d bytes, but we sent %d bytes" % (len(data), bytes_sent))
            return data
        except socket.error as e:
            print("ERROR:\t{}".format(e.message))
            return ""

    @staticmethod
    def __print_error(msg):
        if config.VERBOSE_LEVEL >= config.VERBOSE_LEVEL_PRINT_ERROR_MESSAGES:
            print("ERROR:\t{}".format(msg))

    def __connect_to_server(self):
        num_of_tries = 0
        connection_to_victim = None
        while True:
            try:
                if self.unix_socket == "":
                    print("Connecting to victim using TCP socket {}: {}".format(self.ip, self.port))
                    connection_to_victim = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    connection_to_victim.settimeout(config.TCP_SOCKET_TIMEOUT)
                    connection_to_victim.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    connection_to_victim.connect((self.ip, self.port))
                else:
                    print("Connecting to victim using UNIX socket {}".format(self.unix_socket))
                    connection_to_victim = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    connection_to_victim.settimeout(config.UNIX_SOCKET_TIMEOUT)
                    connection_to_victim.connect(self.unix_socket)
                break
            except socket.error as e:
                print("ERROR:\t{}".format(e))
                num_of_tries += 1
                if config.NUMBER_OF_RECONNECTS == num_of_tries:
                    time.sleep(config.TIME_BETWEEN_RECONNECTS)
                    return None
        return connection_to_victim
