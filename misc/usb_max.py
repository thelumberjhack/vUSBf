## This file is for use with Scapy
## See http://www.secdev.org/projects/scapy for more information
## This file is for use with the GoodFET framework for the Facedancer10 project
##  for interacting with the MAX3420 chip for USB interaction.
## Copyright (C) Ryan Speers <ryan@rmspeers.com> 2012
## This program is published under a GPLv2 license

"""
USB according to the MAX2420 IC.
"""

import re, struct

from scapy.packet import *
from scapy.fields import *

# Get Descriptor codes
GD_DEVICE           =0x01   # Get device descriptor: Device
GD_CONFIGURATION    =0x02   # Get device descriptor: Configuration
GD_STRING           =0x03   # Get device descriptor: String
GD_HID              =0x21   # Get descriptor: HID
GD_REPORT           =0x22   # Get descriptor: Report
_gd_descriptor_codes = {
    GD_DEVICE:          "Device",
    GD_CONFIGURATION:   "Configuration",
    GD_STRING:          "String",
    GD_HID:             "HID",
    GD_REPORT:          "Report",
}

# Standard USB Requests
SR_GET_STATUS       =0x00   # Get Status
SR_CLEAR_FEATURE    =0x01   # Clear Feature
SR_RESERVED         =0x02   # Reserved
SR_SET_FEATURE      =0x03   # Set Feature
SR_SET_ADDRESS      =0x05   # Set Address
SR_GET_DESCRIPTOR   =0x06   # Get Descriptor
SR_SET_DESCRIPTOR   =0x07   # Set Descriptor
SR_GET_CONFIGURATION    =0x08   # Get Configuration
SR_SET_CONFIGURATION    =0x09   # Set Configuration
SR_GET_INTERFACE    =0x0a   # Get Interface
SR_SET_INTERFACE    =0x0b   # Set Interface
_sr_request_codes = {
    SR_GET_STATUS:          "Get Status",
    #TODO if needed
}

_setup_bRequest_types = {
    0x00:   "GET_STATUS",
    0x01:   "CLEAR_FEATURE",
    0x03:   "SET_FEATURE",
    0x05:   "SET_ADDRESS",
    0x06:   "GET_DESCRIPTOR",
    0x07:   "SET_DESCRIPTOR",
    0x08:   "GET_CONFIGURATION",
    0x09:   "SET_CONFIGURATION",
}

#bmAttributes is an 8-bit flag field.
_config_bmAttributes_names = [
    # D4..0 Reserved, set to 0.
    "Reserved0", "Reserved1", "Reserved2", "Reserved3", "Reserved4",
    "RemoteWakeup", # D5 Remote Wakeup
    "SelfPowered",  # D6 Self Powered
    "Reserved7",    # D7 Reserved, set to 1. (USB 1.0 Bus Powered)
]

### Fields ###
# No custom fields are defined yet.

### Layers ###



class USBDescriptorHID(Packet):
    '''One of the descriptors that can be nested into a full Configuration Descriptor.'''
    name = "USB HID Descriptor"
    fields_desc = [
        ByteField("bLength", 0x09),
        XByteField("bDescriptorType", 0x21),# type 33d=HID
        XLEShortField("bcdHID", 0x0110),    # bcdHID(L/H) Rev 1.1
        ByteField("bCountryCode", 0),       # 0=None
        ByteField("bNumDescriptors", 1),    # 1 report descriptor
        ByteField("bDescriptorType0", 0x22), # 0x22=report TODO name was overlapping!
        LEShortField("wDescriptorLength", 43), #report descriptor size is 43 bytes
    ]


class USBDescriptorInterface(Packet):
    '''One of the descriptors that can be nested into a full Configuration Descriptor.'''
    name = "USB Interface Descriptor"
    fields_desc = [
        ByteField("bLength", 0x09),
        XByteField("bDescriptorType", 0x04),# type = IF
        #bInterfaceNumber indicates the index of the interface descriptor.
        # Is zero based, and incremented once for each new interface descriptor.
        ByteField("bInterfaceNumber", 0),   # default IF #0
        ByteField("bAlternateSetting", 0),
        #bNumEndpoints indicates the number of endpoints used by the interface.
        # Value should exclude endpoint zero, is used to indicate the number of endpoint descriptors to follow.
        ByteField("bNumEndpoints", 1),      # bNum Endpoints
        ByteField("bInterfaceClass", 0x03), # bInterfaceClass = HID TODO enumeration
        ByteField("bInterfaceSubClass", 0x00),
        ByteField("bInterfaceProtocol", 0x00),
        #Index of String Descriptor Describing this interface
        ByteField("iInterface", 0x00),
        # TODO implement as a PacketListField linked to the right item
        PacketField("hid_list", USBDescriptorHID(), USBDescriptorHID),
        # Number of Endpoint items is given by bNumEndpoints
        # TODO this will currently only instantiate one Endpoint by default, but we'd
        #      like this to instantiate the amount based on the setting of bNumEndpoints,
        #      and furthermore, the Endpoint IDs should increment if possible.
        PacketListField("endpoint_list", USBDescriptorEndpoint(), USBDescriptorEndpoint, \
            count_from=lambda pkt: pkt.bNumEndpoints),
    ]

class USBStringDescriptor(Packet):
    '''
    During the setup process provides the string descriptors requested for
    the device being enumerated.
    Reference: http://www.beyondlogic.org/usbnutshell/usb5.shtml
    '''
    name = "USB String Descriptor Response"
    fields_desc = [
        FieldLenField("bLength", None, length_of="string", fmt="B", adjust=lambda pkt,x: x+2),
        ByteField("bDescriptorType", 0x03), # 3=String
        StrLenField("string", "", codec="utf-16-le", length_from=lambda pkt: pkt.bLength-2),
    ]

    def answers(self, other):
        '''
        If the USBSetup packet has a standard request to send a descriptor
        and it is a string descriptor request.
        '''
        if isinstance(other, USBSetup):
            #Standard Request and Send Descriptor and String Request
            if other.bmRequestType & 0x60 == 0x00 and  \
               other.bRequest == SR_GET_DESCRIPTOR and \
               other.wValueH == GD_STRING:
                return True
        return False

    def getBuiltArray(self):
        return map(lambda x: ord(x), str(self))

    def getDescLen(self):
        if self.bLength != None:
            return self.bLength
        else:
            return len(self.string)*2+2

class USBStringDescriptorLanguage(USBStringDescriptor):
    '''
    During the setup process provides the string descriptors requested for
    the device being enumerated. String Descriptor 0 is special, and is a list
    of the supported language codes.
    Reference: http://www.usb.org/developers/data/USB_LANGIDs.pdf
    '''
    name = "USB String Descriptor Language Response"
    fields_desc = [
        #FieldLenField("bLength", None, count_of="string", fmt="B", adjust=lambda pkt,x: (x*2)+2),
        FieldLenField("bLength", None, length_of="string", fmt="B", adjust=lambda pkt,x: x+2),
        ByteField("bDescriptorType", 0x03), # 3=String
        # TODO implement proper list of enumerated shorts for language codes
        #FieldListField("string", [XLEShortField("language", 0x0409)], XLEShortField, count_from=lambda pkt:(pkt.bLength-2)/2),
        StrLenField("string", "\x09\x04", length_from=lambda pkt: pkt.bLength-2), #default English-United States
    ]

    def addLanguage(self, hexcode):
        packed = struct.pack("<H", hexcode)
        if packed not in self.string: #TODO make search based on actual fields
            self.string += packed
            return True
        else:
            return False

### Bindings ###
#bind_layers( Outer, Inner, field_type=0)

### DLT Types ###
# No DLT is applicable for this layer definition.

### Test Cases ###
import unittest

class TestDeviceDescriptor(unittest.TestCase):
    DD=[0x12,       # bLength = 18d
    0x01,           # bDescriptorType = Device (1)
    0x00,0x01,      # bcdUSB(L/H) USB spec rev (BCD)
    0x00,0x00,0x00, # bDeviceClass, bDeviceSubClass, bDeviceProtocol
    0x40,           # bMaxPacketSize0 EP0 is 64 bytes
    0x6A,0x0B,      # idVendor(L/H)--Maxim is 0B6A
    0x46,0x53,      # idProduct(L/H)--5346
    0x34,0x12,      # bcdDevice--1234
    1,2,3,          # iManufacturer, iProduct, iSerialNumber
    1];

    def test_default(self):
        pkt = USBDeviceDescriptor()
        self.assertEqual(pkt.getDescLen(), pkt.bLength, 'USBDeviceDescriptor length should be from bLength.')
        self.assertEqual(pkt.getDescLen(), self.DD[0], 'USBDeviceDescriptor length is wrong.')
        self.assertEqual(pkt.getBuiltArray(), self.DD, 'USBDeviceDescriptor default construction is wrong.')

class TestConfigurationDescriptor(unittest.TestCase):
    #Configuration Descriptor
    CD=[0x09,           # bLength
    0x02,           # bDescriptorType = Config
    0x22,0x00,      # wTotalLength(L/H) = 34 bytes
    0x01,           # bNumInterfaces
    0x01,           # bConfigValue
    0x00,           # iConfiguration
    0xE0,           # bmAttributes. b7=1 b6=self-powered b5=RWU supported
    0x01,           # MaxPower is 2 ma
    # INTERFACE Descriptor
    0x09,           # length = 9
    0x04,           # type = IF
    0x00,           # IF #0
    0x00,           # bAlternate Setting
    0x01,           # bNum Endpoints
    0x03,           # bInterfaceClass = HID
    0x00,0x00,      # bInterfaceSubClass, bInterfaceProtocol
    0x00,           # iInterface
    # HID Descriptor--It's at CD[18]
    0x09,           # bLength
    0x21,           # bDescriptorType = HID
    0x10,0x01,      # bcdHID(L/H) Rev 1.1
    0x00,           # bCountryCode (none)
    0x01,           # bNumDescriptors (one report descriptor)
    0x22,           # bDescriptorType   (report)
    43,0,                   # CD[25]: wDescriptorLength(L/H) (report descriptor size is 43 bytes)
    # Endpoint Descriptor
    0x07,           # bLength
    0x05,           # bDescriptorType (Endpoint)
    0x83,           # bEndpointAddress (EP3-IN)
    0x03,           # bmAttributes  (interrupt)
    64,0,                   # wMaxPacketSize (64)
    10];

    def test_default(self):
        pkt = USBConfigurationDescriptor()
        self.assertEqual(pkt.getDescLen(), pkt.wTotalLength, 'USBConfigurationDescriptor length should be from wTotalLength.')
        self.assertEqual(pkt.getDescLen(), self.CD[2], 'USBConfigurationDescriptor length is wrong.')
        self.assertEqual(pkt.getBuiltArray(), self.CD, 'USBConfigurationDescriptor default construction is wrong.')

class TestStringDescriptor(unittest.TestCase):
    def test_default_language(self):
        pkt = USBStringDescriptorLanguage()
        pkt.addLanguage(0x0409)
        self.assertEqual("\x04\x03\x09\x04", str(pkt), 'USBStringDescriptorLanguage default construction is wrong.')

    def test_default_strings(self):
        pkt = USBStringDescriptor()
        pkt.string = "Maxim"
        self.assertEqual("\x0c\x03M\x00a\x00x\x00i\x00m\x00", str(pkt), 'USBStringDescriptor default construction is wrong.')
        pkt.string = "MAX3420E Enum Code"
        self.assertEqual("\x26\x03M\x00A\x00X\x003\x004\x002\x000\x00E\x00 \x00E\x00n\x00u\x00m\x00 \x00C\x00o\x00d\x00e\x00", str(pkt), 'USBStringDescriptor default construction is wrong.')
        pkt.string = "S/N 3420E"
        self.assertEqual("\x14\x03S\x00/\x00N\x00 \x003\x004\x002\x000\x00E\x00", str(pkt), 'USBStringDescriptor default construction is wrong.')
        self.assertEqual(pkt.getDescLen(), 0x14, 'USBStringDescriptor length is wrong (%02x).' % pkt.getDescLen())

if __name__ == '__main__':
    unittest.main()
