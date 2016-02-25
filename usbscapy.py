"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

import struct
from scapy.all import *
from scapy.fields import *

#####################################
####### SCAPY EXTENSION STUFF #######
#####################################

# XLEShortField
class XLEShortField(LEShortField, XShortField):
    def i2repr(self, pkt, x):
        return XShortField.i2repr(self, pkt, x)


# XLEIntField
class XLEIntField(LEIntField, XIntField):
    def i2repr(self, pkt, x):
        return XIntField.i2repr(self, pkt, x)


####################################
####### REDIR SPECIFIC STUFF #######
####################################

usbredir_type_enum = {  # CONTROL PACKETS
                        0: "hello",
                        1: "device_connect",
                        2: "device_disconnect",
                        3: "reset",
                        4: "interface_info",
                        5: "ep_info",
                        6: "set_configuration",
                        7: "get_configuration",
                        8: "configuration_status",
                        9: "set_alt_setting",
                        10: "get_alt_setting",
                        11: "alt_setting_status",
                        12: "start_iso_stream",
                        13: "stop_iso_stream",
                        14: "iso_stream_status",
                        15: "start_interrupt_receiving",
                        16: "stop_interrupt_receiving",
                        17: "interrupt_receiving_status",
                        18: "alloc_bulk_streams",
                        19: "free_bulk_streams",
                        20: "bulk_streams_status",
                        21: "cancel_data_packet",
                        22: "filter_reject",
                        23: "filter_filter",
                        24: "device_disconnect_ack",  # DATA PACKETS
                        100: "data_control_packet",
                        101: "data_bulk_packet",
                        102: "data_iso_packet",
                        103: "data_interrupt_packet"}


usbredir_caps_enum = {
    # Supports USB 3 bulk streams
    0: "usb_redir_cap_bulk_streams",
    # The device_connect packet has the device_version_bcd field
    1: "usb_redir_cap_connect_device_version",
    # Supports usb_redir_filter_reject and usb_redir_filter_filter pkts
    2: "usb_redir_cap_filter",
    # Supports the usb_redir_device_disconnect_ack packet
    3: "usb_redir_cap_device_disconnect_ack",
    # The ep_info packet has the max_packet_size field
    4: "usb_redir_cap_ep_info_max_packet_size",
    # Supports 64 bits ids in usb_redir_header
    5: "usb_redir_cap_64bits_ids",
    # Supports 32 bits length in usb_redir_bulk_packet_header
    6: "usb_redir_cap_32bits_bulk_length",
    # Supports bulk receiving / buffered bulk input
    7: "usb_redir_cap_bulk_receiving",
};


# DO NOT FUZZ THE FOLLOWING REDIR SPECIFIC PACKAGES! FUZZING WILL CAUSE IN QEMU CRASH!
class usbredirheader(Packet):
    name = "UsbredirPacket"
    fields_desc = [LEIntEnumField("Htype", -1, usbredir_type_enum),
                   LEIntField("HLength", 0),
                   LEIntField("Hid", -1)]


# Redir Packet No. 0 (redir hello)
class hello_redir_header(Packet):
    name = "Hello_Packet"
    fields_desc = [StrLenField("version", "", length_from=64),  # StrLenField("caps", "", length_from=4)]
                   LEIntField("capabilites", 1)]


class hello_redir_header_host(Packet):
    name = "Hello_Packet_Host"
    fields_desc = [StrLenField("version", "", length_from=56)]


# Redir Packet No. 1 (redir connect)
class connect_redir_header(Packet):
    name = "Connect_Packet"
    fields_desc = [ByteField("speed", 0),
                   XByteField("device_class", 0),
                   XByteField("device_subclass", 0),
                   XByteField("device_protocol", 0),
                   XLEShortField("vendor_id", 0),
                   XLEShortField("product_id", 0),
                   XLEShortField("device_version_bcd", 0)]


# Redir Packet No. 4 (interface info)   [SIZE 132 BYTES]
class if_info_redir_header(Packet):
    name = "Interface Info Packet"
    fields_desc = [LEIntField("interface_count", None),
                   FieldListField("interface", None, ByteField("Value", 0), length_from=lambda p: 32),
                   FieldListField("interface_class", None, ByteField("Value", 0), length_from=lambda p: 32),
                   FieldListField("interface_subclass", None, ByteField("Value", 0), length_from=lambda p: 32),
                   FieldListField("interface_protocol", None, ByteField("Value", 0), length_from=lambda p: 32)]


# Redir Packet No. 5 (endpoint info)    [SIZE 160 BYTES]
class ep_info_redir_header(Packet):
    name = "Endpoint Info Packet"
    fields_desc = [FieldListField("ep_type", None, ByteEnumField("type_value", 0, {0: "type_control",
                                                                                   1: "type_iso",
                                                                                   2: "type interrupt",
                                                                                   255: "type invalid", })
                                  , length_from=lambda p: 32),
                   FieldListField("interval", None, ByteField("Value", 0), length_from=lambda p: 32),
                   FieldListField("interface", None, ByteField("Value", 0), length_from=lambda p: 32),
                   FieldListField("max_packet_size", None, XLEShortField("Value", 0), length_from=lambda p: 32 * 2)]


# Redir Packet No. 100 (data control)   [SIZE 10 BYTES]
class data_control_redir_header(Packet):
    name = "Data_Control_Packet"
    fields_desc = [ByteField("endpoint", 0),
                   ByteField("request", 0),
                   ByteField("requesttype", 0),
                   ByteField("status", 0),
                   XLEShortField("value", 0),
                   LEShortField("index", 0),
                   LEShortField("length", 0)]


# Redir Packet No. 101 (data bulk)      [SIZE 8 BYTES]
class data_bulk_redir_header(Packet):
    name = "Data_Bulk_Packet"
    fields_desc = [ByteField("endpoint", 0),
                   ByteField("status", 0),
                   LEShortField("length", None),
                   LEIntField("stream_id", None),
                   LEShortField("length_high", None)]


# Redir Packet No. 102 (data iso)       [SIZE 4 BYTES]
class data_iso_redir_header(Packet):
    name = "Data_Iso_Packet"
    fields_desc = [ByteField("endpoint", 0),
                   ByteField("status", 0),
                   LEShortField("length", 0)]


# Redir Packet No. 103 (data interrupt) [SIZE 4 BYTES]
class data_interrupt_redir_header(Packet):
    name = "Data_Interrupt_Packet"
    fields_desc = [ByteField("endpoint", 0),
                   ByteField("status", 0),
                   LEShortField("length", 0)]


redir_specific_type = [[0, hello_redir_header],
                       [1, connect_redir_header],
                       [100, data_control_redir_header],
                       [101, data_bulk_redir_header],
                       [102, data_iso_redir_header],
                       [103, data_interrupt_redir_header]]


##################################
####### USB SPECIFIC STUFF #######
####### ENUMARATION PHASE  #######
##################################

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


# USB Header (URB - replaced by usbredirheader)
class usb_header(Packet):
    name = "USB_Packet"
    fields_desc = [
                     XLongField("id", 0xffff88003720d540),
                     ByteField("type", 43),
                     ByteField("transfer type", 2),
                     ByteField("endpoint", 80),
                     ByteField("device", 0),
                     LEShortField("bus_id", 0),
                     ByteField("device_setup_request", 0),
                     ByteField("data_present", 0),
                     LELongField("urb_sec", 0),
                     LEIntField("urb_usec", 0),
                     LEIntField("urb_status", 0),
                     LEIntField("urb_length", 0),
                     LEIntField("data_length", 0)
                   ]


# Generic USB Descriptor Header
class usb_generic_descriptor_header(Packet):
    name = "USB_GENERIC_DESCRIPTOR_HEADER"
    fields_desc = [
                     ByteField("bLength", 0),
                     XByteField("bDescriptorType", 0x1)
                  ]
"""
class USBSetup(Packet):
    '''
    Represents the Setup Packets that a device receives from the host.
    Reference: http://www.beyondlogic.org/usbnutshell/usb6.shtml#SetupPacket
    '''
    name = "USB Setup"
    fields_desc = [
        #bmRequestType can be broken down further:
        # D7 Data Phase Transfer Direction (0 = Host to Device, 1 = Device to Host)
        # D6..5 Type (0 = Standard, 1 = Class, 2 = Vendor, 3 = Reserved)
        # D4..0 Recipient (0 = Device, 1 = Interface, 2 = Endpoint, 3 = Other, 4..31 = Reserved)
        XByteField("bmRequestType", 0),
        XByteEnumField("bRequest", 0x00, _setup_bRequest_types),
        # The wValueH could be interpreted via _gd_descriptor_codes{}
        XLEShortField("wValue", 0),
        XLEShortField("wIndex", 0),
        XLEShortField("wLength", 0),
    ]

    def mysummary(self):
        if self.bmRequestType == 0x00 and self.bRequest == 0x05: #SET_ADDRESS
            return self.sprintf("Setup %USBSetup.bRequest%: device address=" + str(self.wValue))
        elif self.bmRequestType == 0x00 and self.bRequest == 0x09:
            return self.sprintf("Setup %USBSetup.bRequest%: desired bConfigurationValue=%USBSetup.wValue%")
        return self.sprintf("Setup bmRequestType=%USBSetup.bmRequestType%, bRequest=%USBSetup.bRequest%, wValue=%USBSetup.wValue%, wIndex=%USBSetup.wIndex%, wLength=%USBSetup.wLength%")

    def getRequestLength(self):
        '''Return the 16-bit length defined in the setup packet.'''
        return (self.wLength&0xFF) + 256*(self.wLength >> 8)

    @property
    def wValueH(self):
        return (self.wValue >> 8)
    @property
    def wValueL(self):
        return (self.wValue & 0xFF)
    @property
    def wIndexL(self):
        return (self.wIndex & 0xFF)
"""


# USB Device Descriptor Packet (DescriptorType 0x01)
class USBDeviceDescriptor(Packet):
    '''During the setup process provides the descriptor of the device being enumerated.'''
    name = "USB_Device_Descriptor"
    fields_desc = [ByteField("bLength", 18),
                   XByteField("bDescriptorType", 0x01),
                   XLEShortField("bcdUSB", 0x0),
                   XByteField("bDeviceClass", 0x1),
                   ByteField("bDeviceSubClass", 0),
                   ByteField("bDeviceProtocol", 0),
                   ByteField("bMaxPacketSize", 0),
                   XLEShortField("isVendor", 0x0),
                   XLEShortField("idProduct", 0x0),
                   XLEShortField("bcdDevice", 0x0),
                   #Three string descriptors exist to provide details of the manufacturer,
                   # product and serial number. There is no requirement to have string
                   # descriptors. If none is present, a index of zero should be used.
                   ByteField("iManufacturer", 0),
                   ByteField("iProduct", 0),
                   ByteField("iSerialNumber", 0),
                   #bNumConfigurations defines num. of configs the device supports at its current speed.
                   ByteField("bNumConfigurations", 1)]

    def answers(self, other):
        '''
        If the USBSetup packet has a standard request to send a descriptor
        and it is a device descriptor request.
        '''
        if isinstance(other, USBSetup):
            #Standard Request and Send Descriptor and Device Descriptor Request
            if other.bmRequestType & 0x60 == 0x00 and  \
               other.bRequest == SR_GET_DESCRIPTOR and \
               other.wValueH == GD_DEVICE:
                return True
        return False

    def getBuiltArray(self):
        return map(lambda x: ord(x), str(self))

    def getDescLen(self):
        return self.bLength

# USB Configuration Descriptor
class USBConfigurationDescriptor(Packet):
    '''
    During the setup process provides the config descriptor of the device
    being enumerated. When the configuration descriptor is read, it returns the
    entire configuration hierarchy which includes all related interface and
    endpoint descriptors.
    Reference: http://www.beyondlogic.org/usbnutshell/usb5.shtml
    '''
    name = "USB_Configuration_Descriptor"
    fields_desc = [ByteField("bLength", 9),  # Size of Descriptor in Bytes
                   XByteField("bDescriptorType", 0x02),  # Configuration Descriptor (0x02)
                   #The wTotalLength field reflects the number of bytes in the hierarchy.
                   XLEShortField("wTotalLength", 0),  # Total length in bytes of data returned
                   ByteField("bNumInterfaces", None),  # Number of Interfaces
                   #bConfigurationValue is used by the SetConfiguration request to select this configuration.
                   ByteField("bConfigurationValue", None),  # Value to use as an argument to select this configuration
                   ByteField("iConfiguration", None),  # Index of String Descriptor describing this configuration
                   FlagsField("bmAttributes", 0b11100000, 8, [
                       "Reserved_D0",  # Reserved Bit
                       "Reserved_D1",  # Reserved Bit
                       "Reserved_D2",  # Reserved Bit
                       "Reserved_D3",  # Reserved Bit
                       "Reserved_D4",  # Reserved Bit
                       "Remote_Wakeup",  # D5 Remote Wakeup
                       "Self_Powered",  # D6 Self Powered
                       "Reserved_D7",  # D7 Reserved: Must be 1 for USB1.1 and higher
                   ]),
                   ByteField("bMaxPower", None)  # Maximum Power consumption in 2mA units
    ]

    def answers(self, other):
        '''
        If the USBSetup packet has a standard request to send a descriptor
        and it is a device descriptor request.
        '''
        if isinstance(other, USBSetup):
            #Standard Request and Send Descriptor and Configuration Request
            if other.bmRequestType & 0x60 == 0x00 and  \
               other.bRequest == SR_GET_DESCRIPTOR and \
               other.wValueH == GD_CONFIGURATION:
                return True
        return False

    def getBuiltArray(self):
        return map(lambda x: ord(x), str(self))

    def getDescLen(self):
        return self.wTotalLength

# USB Interface_Descriptor
class USBInterfaceDescriptor(Packet):
    '''One of the descriptors that can be nested into a full Configuration Descriptor.'''
    name = "USB_Interface_Descriptor"
    fields_desc = [ByteField("bLength", 0x9),  # Size of Descriptor in Bytes (9 Bytes)
                   XByteField("bDescriptorType", 0x04),  # Configuration Descriptor (0x04)
                   #bInterfaceNumber indicates the index of the interface descriptor.
                   # Is zero based, and incremented once for each new interface descriptor.
                   ByteField("bInterfaceNumber", None),  # Number of Interface
                   ByteField("bAlternateSetting", None),  # Value used to select alternative setting
                   #bNumEndpoints indicates the number of endpoints used by the interface.
                   # Value should exclude endpoint zero, is used to indicate the number of endpoint descriptors to follow.
                   ByteField("bNumEndpoints", None),  # Number of Endpoints used for this interface
                   XByteField("bInterfaceClass", None),  # Class Code [0x08: MASSSTORAGE, ...]
                   XByteField("bInterfaceSubClass", None),  # Subclass Code
                   XByteField("bInterfaceProtocol", None),  # Protocol Code
                   ByteField("iInterface", None)  # Index of String Descriptor describing this interface
    ]


# USB Endpoint Descriptors
class USBEndpointDescriptor(Packet):
    '''One of the descriptors that can be nested into a full Configuration Descriptor.'''
    name = "USB_Endpoint_Descriptor"
    fields_desc = [ByteField("bLength", 7),  # Size of Descriptor in Bytes (7 Bytes)
                   XByteField("bDescriptorType", 0x05),  # Configuration Descriptor (0x05) #type = endpoint
                   #Endpoint Address
                   #Bits 0..3b Endpoint Number.
                   #Bits 4..6b Reserved. Set to Zero
                   #Bits 7 Direction 0 = Out, 1 = In (Ignored for Control Endpoints)
                   XByteField("bEndpointAddress", 0x83), # bEndpointAddress (default EP3-IN)
                   ByteField("bmAttributes", 3),         # 3=interrupt
                   #TODO split bmAttributes by flags, but it changes based on endpoint type
                   #bmAttributes: Bits 0..1 Transfer Type
                   #BitEnumField("bmAttributes_transfertype", 0b11, 2, \
                   #    {0x0:"Control", 0x1:"Isochronous", 0x2:"Bulk", 0x3:"Interrupt"}),
                   LEShortField("wMaxPacketSize", None),
                   # Maximum Packet Size this endpoint is cabable of sending or recving
                   ByteField("bInterval", None)  # Interval for polling endpoint data transfer. Value in frame counts
    ]



class USBStringDescriptor(Packet):
    '''
    During the setup process provides the string descriptors requested for
    the device being enumerated.
    Reference: http://www.beyondlogic.org/usbnutshell/usb5.shtml
    '''
    name = "USB_String_Descriptor"
    fields_desc = [
                   FieldLenField("bLength", None, length_of="string", fmt="B", adjust=lambda pkt,x: x+2),
                   ByteField("bDescriptorType", 0x03), # 3=String
                   StrLenField("string", "", length_from=lambda pkt: pkt.bLength-2),
    ]

class USBStringDescriptorLanguage(USBStringDescriptor):
    '''
    During the setup process provides the string descriptors requested for
    the device being enumerated. String Descriptor 0 is special, and is a list
    of the supported language codes.
    Reference: http://www.usb.org/developers/data/USB_LANGIDs.pdf
    '''
    name = "USB_String_Descriptor_LangID"
    fields_desc = [
        FieldLenField("bLength", None, length_of="wLANGID", fmt="B", adjust=lambda pkt,x: x+2),
        ByteField("bDescriptorType", 0x03), # 3=String
        # TODO implement proper list of enumerated shorts for language codes
        #FieldListField("string", [XLEShortField("language", 0x0409)], XLEShortField, count_from=lambda pkt:(pkt.bLength-2)/2),
        StrLenField("wLANGID", "\x09\x04", length_from=lambda pkt: pkt.bLength-2), #default English-United States
    ]

    def addLanguage(self, hexcode):
        packed = struct.pack("<H", hexcode)
        if packed not in self.string: #TODO make search based on actual fields
            self.string += packed
            return True
        else:
            return False


class USBHIDDescriptor(Packet):
    '''One of the descriptors that can be nested into a full Configuration Descriptor.'''
    name = "USB HID Descriptor"
    fields_desc = [
        ByteField("bLength", 0x09),
        XByteField("bDescriptorType", 0x21),# type 33d=HID
        XLEShortField("bcdHID", 0x0110),    # bcdHID(L/H) Rev 1.1
        ByteField("bCountryCode", 0),       # 0=None
        ByteField("bNumDescriptors", 1),    # 1 report descriptor
        XByteField("bDescriptorType0", 0x22), # 0x22=report TODO name was overlapping!
        LEShortField("wDescriptorLength", 43), #report descriptor size is 43 bytes
    ]


class USBHIDReportExtension(Packet):
    name = "USB_HID_Report_Extension"
    fields_desc = [XByteField("bDescriptorType2", 0x22),  # 0x22 REPORT DESCRIPTOR # 0x23 PYSICAL DESCRIPTOR
                   LEShortField("wDescriptorLength", 0x00)
    ]


class USBHIDReportDescriptor(Packet):
    name = "USB_HID_Report_Descriptor"
    fields_desc = []


descriptor_types = {
                        0x01: USBDeviceDescriptor,
                        0x02: USBConfigurationDescriptor,
                        0x03: USBStringDescriptor,
                        0x04: USBInterfaceDescriptor,
                        0x05: USBEndpointDescriptor,
                        0x09: USBHIDDescriptor
                   }


## PROTOTYPE FOR USB_HUB_DESCRIPTOR ##
##
## typedef struct _USB_HUB_DESCRIPTOR {
##  UCHAR  bDescriptorLength;
##  UCHAR  bDescriptorType;
##  UCHAR  bNumberOfPorts;
##  USHORT wHubCharacteristics;
##  UCHAR  bPowerOnToPowerGood;
##  UCHAR  bHubControlCurrent;
##  UCHAR  bRemoveAndPowerMask[64];
## } USB_HUB_DESCRIPTOR, *PUSB_HUB_DESCRIPTOR;



##############################################
####### USB MASSSTORAGE SPECIFIC STUFF #######
######  SCSI                           #######
##############################################

# dCBWSignatur
dCBWSignature_magic_number = 0x43425355

#dCSWSignatur
dCSWSignature_magic_number = 0x53425355

# Command Generic Header
class massstorage_generic(Packet):
                name = "Massstorage_Generic"
                fields_desc = [ XLEIntField("dSignature", 0)]

# Command Block Wrapper  (CBW)          [SIZE: 12 Bytes]
class massstorage_cbw(Packet):
                                name = "Massstorage_CBW"
                                fields_desc = [ XLEIntField("dCBWSignature", 0),
                                IntField("dCBWTag", None),
                                XLEIntField("dCBWDataTransferLength", None),
                                ByteField("bmCBWFlags", None),
                                ByteField("bCBWLUN", None),
                                ByteField("bCBWCBLength", None)
                                ]

# Command Status Wrapper (CSW)
class massstorage_csw(Packet):
                name = "Masstorage_CSW"
                fields_desc = [ XLEIntField("dCSWSignature", 0),
                                IntField("dCSWTag", None),
                                XLEIntField("dCSWDataResidue", None),
                                                                ByteField("bCSWStatus", None)
                                ]

###################################
####### SCSI SPECIFIC STUFF #######
###################################

# SCSI_INQUIRY STRING LENGTH
SCSI_INQUIRY_VENDOR_ID_LENGTH = 8
SCSI_INQUIRY_PRODUCT_ID_LENGTH = 16
SCSI_INQUIRY_PRODUCT_REVISION_LEVEL_LENGTH = 4

# INQUIRY SCSI (SIZE: 36 Bytes)
class scsi_inquiry(Packet):
                name = "SCSI_Inquiry"
                fields_desc = [ ByteField("peripheral", None),
                                ByteField("RMB", None),
                                ByteField("version", None),
                                ByteField("?", None),
                                ByteField("additional_length", None),
                                ByteField("??", None),
                                ByteField("???", None),
                                ByteField("????", None),

                                StrFixedLenField("vendor_id", None, SCSI_INQUIRY_VENDOR_ID_LENGTH),
                                StrFixedLenField("product_id", None, SCSI_INQUIRY_PRODUCT_ID_LENGTH),
                                StrFixedLenField("product_revision_level", None, SCSI_INQUIRY_PRODUCT_REVISION_LEVEL_LENGTH)
                                ]

# Raw INQUIRY SCSI
class scsi_raw_inquiry(Packet):
                                name = "SCSI_Raw_Inquiry"
                                fields_desc = [ ByteField("peripheral", None),
                                                                ByteField("RMB", None),
                                                                ByteField("version", None),
                                                                ByteField("?", None),
                                                                ByteField("additional_length", None),
                                                                ByteField("??", None),
                                                                ByteField("???", None),
                                                                ByteField("????", None),
                                                                #PAYLOAD VENDOR ID[8] PRODUCT ID[16] PRODUCT REV[4]
                                                                ]

# READ CAPICITY SCSI
#class scsi_read_capicity(Packet):
#               name = "SCSI_READ_CAPICITY"
#               fields_desc = [ ByteField("opcode", 0x25),
#                               ByteField("reserved", None),
#                               XLEIntField("logical_block_adress", None),
#                               ShortField("reserverd", None),
#                               ByteField("reserverd", None),
#                               XByteField("control", None)
#               ]

# READ CAPICITY SCSI RESONSE
class scsi_read_capicity(Packet):
                name = "SCSI_READ_CAPICITY_RESPONSE"
                fields_desc = [ XLEIntField("returned_logic_block_addr", None),
                                                XLEIntField("block_length", None) ]

# MODE SELECT (6) SCSI RESPONSE
class scsi_mode_6(Packet):
                name = "SCSI_MODE_SELECT_(6)_RESPONSE"
                fields_desc = [ ByteField("mode_data_length", None),
                                ByteField("medium_field", None),
                                ByteField("dev-specific_parameter", None),
                                ByteField("block_desc_length", None) ]

# SCSI COMMAND LIST [OPCODE, NAME, SCAPYNAME]
SCSI_COMMAND_LIST = [   ['\x04', "FORMAT UNIT", None],
                                                ['\x12', "INQUIRY", scsi_inquiry],
                                                ['\x15', "MODE SELECT (6)", scsi_mode_6],
                                                ['\x55', "MODE SELECT (10)", None],
                                                ['\x1a', "MODE SENSE (6)", scsi_mode_6],
                                                ['\x5a', "MODE SENSE (10)", None],
                                                ['\x1e', "PREVENT ALLOW MEDIUM REMOVAL", None],
                                                ['\x08', "READ (6)", None],
                                                ['\x28', "READ (10)", None],
                                                ['\xa8', "READ (12)", None],
                                                ['\x25', "READ CAPACITY (10)", scsi_read_capicity],
                                                ['\x23', "READ FORMAT CAPACITY", None],
                                                ['\x43', "READ TOC/PMA/ATIP", None],
                                                ['\xa0', "REPORT LUNS", None],
                                                ['\x03', "REQUEST SENSE", None],
                                                ['\x1d', "SEND DIAGNOSITC", None],
                                                ['\x1b', "START STOP UNIT", None],
                                                ['\x35', "SYNCHRONIZE CACHE (10)", None],
                                                ['\x00', "TEST UNIT READY", None],
                                                ['\x2f', "VERIFY (10)", None],
                                                ['\x0a', "WRITE (6)", None],
                                                ['\x2a', "WRITE (10)", None],
                                                ['\xaa', "WRITE (12)", None]
                                ]

