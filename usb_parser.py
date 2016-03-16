"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

from usbscapy import *


# GENERIC CLASS
class Parser(object):
    __raw = ""

    def __init__(self, raw):
        self.__raw = raw

    def get_scapy_packet(self):
        return None

    def _get_raw(self):
        return self.__raw


# USBREDIR PARSER (USE THIS PARSER ONLY WITH DEVICE DATA)
class USBRedirParser(Parser):
    scapy_data = None

    def __init__(self, raw):
        if raw is None:
            raise Exception("illegal redirData")
        if len(raw) < 16:
            raise Exception("illegal redirData")

        Parser.__init__(self, raw)
        self.scapy_data = self.__parse_raw(raw)

    def get_scapy_packet(self):
        return self.scapy_data

    def get_scapy_layers(self):
        scapy_layers = []
        scapy_layer = copy.copy(self.scapy_data)

        scapy_layers.append(type(scapy_layer))
        while scapy_layer.payload:
            scapy_layer = scapy_layer.payload
            scapy_layers.append(type(scapy_layer))

        return scapy_layers

    def modify_layer(self, layer_type, field, value):
        scapy_layer = self.scapy_data
        if layer_type == type(scapy_layer):
            setattr(scapy_layer, field, value)

        while scapy_layer.payload:
            scapy_layer = scapy_layer.payload
            if layer_type == type(scapy_layer):
                setattr(scapy_layer, field, value)

    @staticmethod
    def __parse_raw(raw):
        header_layer = usbredirheader(raw[0:16])

        Htype = header_layer.Htype
        HLength = header_layer.HLength

        if len(raw) == 16:
            return header_layer

        specific_layer = None

        for layer in redir_specific_type:
            if Htype == layer[0]:
                try:
                    specific_layer = layer[1](raw[16:HLength + 16])
                except Exception:
                    pass
                break

        # UNKNOWN SPECIFIC REDIR HEADER
        if specific_layer is None:
            specific_layer = Raw(raw[16:HLength + 16])
            header_layer = header_layer / specific_layer

        # CONTROL DATA REDIR HEADER
        elif Htype == 100:
            if specific_layer.haslayer(Raw):
                # IF REPORT DESC EXIT
                tmp_value = specific_layer.value
                tmp_value -= 8704

                if 0 <= tmp_value < 256:
                    hid_report = USBHIDReportDescriptor(str(specific_layer.payload))
                    specific_layer.payload = None
                    return header_layer / specific_layer / hid_report

                control_layer = ControlPacketParser(specific_layer.load, specific_layer.request).get_scapy_packet()
                specific_layer[Raw] = None
                header_layer = header_layer / specific_layer / control_layer
            else:
                header_layer = header_layer / specific_layer

        # BULK DTA
        elif Htype == 101 and specific_layer.haslayer(Raw):
            raw_layer = Raw(specific_layer.load)
            specific_layer[Raw] = None
            header_layer = header_layer / specific_layer / raw_layer

        raw = raw[HLength + 16:]
        if raw != "":
            header_layer = header_layer / Raw(raw)
        return header_layer


# USB DESCRIPTOR PARSER (USB REDIR CONTROL DATA)
class ControlPacketParser(Parser):
    scapy_data = None

    def __init__(self, raw, index):
        Parser.__init__(self, raw)
        self.scapy_data = self.__parse_raw(raw, index)
        if self.scapy_data is None:
            raise Exception("Unknown data exception...")

    def get_scapy_packet(self):
        return self.scapy_data

    def __parse_raw(self, data, index):
        if data == "":
            return None

        # GENERIC DESCRIPTOR HEADER
        generic_descriptor_header = usb_generic_descriptor_header(data)
        # print generic_descriptor_header.bLength

        # DEVICE DESCRIPTOR
        if generic_descriptor_header.bDescriptorType == 0x01 and len(data) >= 18:
            # IF LEN == 5 AND TYPE == 1 -> REPORT DESCRIPTOR
            if generic_descriptor_header.bLength < 18:
                return Raw(data)
            new_layer = USBDeviceDescriptor(data[0:generic_descriptor_header.bLength])

        # CONFIGURATION DESCRIPTOR
        elif generic_descriptor_header.bDescriptorType == 0x2 and len(data) >= 9:
            new_layer = USBConfigurationDescriptor(data[0:generic_descriptor_header.bLength])

        # INTERFACE DESCRIPTOR
        elif generic_descriptor_header.bDescriptorType == 0x04 and len(data) >= 9:
            new_layer = USBInterfaceDescriptor(data[0:generic_descriptor_header.bLength])

        # STRING LANGID DESCRIPTOR
        elif generic_descriptor_header.bDescriptorType == 0x03 and index == 0 and len(data) >= 4:
            new_layer = USBStringDescriptorLanguage(data[:generic_descriptor_header.bLength])

        # STRING DESCRIPTOR
        elif generic_descriptor_header.bDescriptorType == 0x03 and index != 0 and len(data) >= 4:
            new_layer = USBStringDescriptor(data[:generic_descriptor_header.bLength])

        # HID DESCRIPTOR
        elif generic_descriptor_header.bDescriptorType == 0x09 and index != 0 and len(data) >= 4:
            new_layer = USBHIDDescriptor(data[:generic_descriptor_header.bLength])

        # ENDPOINT DESCRIPTOR
        elif generic_descriptor_header.bDescriptorType == 0x05 and len(data) >= 7:
            new_layer = USBEndpointDescriptor(data[:generic_descriptor_header.bLength])

        # UNKNOWN DATA
        else:
            if len(data) >= generic_descriptor_header.bLength and generic_descriptor_header.bLength != 0:
                new_layer = Raw(data[:generic_descriptor_header.bLength])
            else:
                new_layer = Raw(data)

        # NEXT LAYER
        if len(data) >= generic_descriptor_header.bLength and generic_descriptor_header.bLength != 0:
            nextLayer = self.__parse_raw(data[generic_descriptor_header.bLength:], index)
            if nextLayer != None:
                new_layer = new_layer / nextLayer

        return new_layer


class DataBulkParser(Parser):
    scapy_data = None
