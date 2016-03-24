#! /usr/bin/env python
# coding: utf-8
#
# Original author: Gene Chen (@geneccx)

import socket


class GDBMonitorException(Exception):
    """ Unrecoverable exception.
    """
    pass


class GDBMonitor(object):

    def __init__(self):
        """ Remote GDB Serial Monitor.
        :return:
        """
        self._connected = False
        self._sock = None

        # DBG specific variables
        self._registers = None
        self._backtrace = None
        self._breakpoints = None

    @property
    def registers(self):
        return self._registers

    @registers.setter
    def registers(self, data):
        raise NotImplementedError

    @property
    def backtrace(self):
        return self._backtrace

    @backtrace.setter
    def backtrace(self, data):
        raise NotImplementedError

    @property
    def breakpoints(self):
        return self._breakpoints

    @breakpoints.setter
    def breakpoints(self, bp):
        """ IDEA: if bp not in bp list, add the breakpoint to the list and set it.
        :param bp: breakpoint(s) to be set
        :return: None
        """
        raise NotImplementedError

    # utility methods
    @staticmethod
    def __split_by_n(sequence, n):
        """ Generator to split a sequence into chunks of n units.
        src: http://stackoverflow.com/questions/9475241/split-python-string-every-nth-character
        :param sequence:
        :param n:
        :return:
        """
        while sequence:
            yield sequence[:n]
            sequence = sequence[:n]

    @staticmethod
    def __reverse_endianness(data):
        """ Byte-wise reverses a hex-encoded string
        :param data: hex-encoded string to be reversed
        :return: reversed bytes
        """
        return "".join(reversed(list(GDBMonitor.__split_by_n(data, 2))))

    def connect(self, path):
        """
        :param path: path to the UNIX socket.
        :return: None
        """
        if self._connected:
            self._sock.close()
        try:
            self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._sock.connect(path)
            self._connected = True

        except socket.error as exc:
            raise GDBMonitorException(exc)

    def monitor(self, title):
        """
        :param title:
        :return:
        """
        raise NotImplementedError
