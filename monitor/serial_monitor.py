#! /usr/bin/env python
# coding: utf-8
#
# Author: Yannick Formaggio
import sys
import socket
import config
import select
import qemu
import logging
import threading


logging.basicConfig(level=logging.DEBUG)


hexdump = lambda x: ":".join("{:02X}".format(ord(c)) for c in x)


class SerialMonitorException(Exception):
    pass


class SerialMonitor(object):

    def __init__(self, qemu, filename, instance_id):
        """
        :param qemu: qemu object
        :param filename: logging file name
        :param instance_id: serial port address
        :return: None
        """
        if not qemu:
            raise SerialMonitorException("qemu object is not defined")
        self.qemu = qemu

        if not filename:
            raise SerialMonitorException("log filename is not defined")

        self.filename = filename[:]

        self.instance_id = instance_id

    def log_reload(self):
        """ Log each time the vm is reloaded.
        :return: None
        """
        with open(self.filename, "a") as log_file:
            log_file.write(config.MESSAGE_VM_RELOAD)

    def monitor(self, title):
        """ Monitoring routine. To be defined by the child class.
        :param title: title of the monitor.
        :return: True when crash found, False otherwise
        """
        pass


class UnixSerialProtocol(object):

    def __init__(self, instance_id):
        self.connected = False
        self.instance_id = instance_id
        self.address = "/tmp/serial_{}_socket".format(self.instance_id)
        self.sock = None
        self.logger = logging.getLogger('UnixSerial')
        self.logger.setLevel(logging.INFO)

    def connect(self):
        if self.connected:
            self.logger.info("Already connected")
            self.close()
        self.logger.debug("Connecting to serial socket")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(config.UNIX_SOCKET_TIMEOUT)
        self.sock.connect(self.address)
        self.connected = True

    def send(self, data):
        self.logger.info("TX: {}".format(hexdump(data)))
        self.sock.send(data)

    def recv(self, n_bytes):
        data = self.sock.recv(n_bytes)
        self.logger.info("[RX] {}".format(hexdump(data)))
        return data

    def is_available(self):
        ready, _, _ = select.select([self.sock], [], [], 0)
        return len(ready) > 0

    def read(self):
        self.logger.debug("Reading serial output")
        msg = ""

        while True:
            try:
                char = self.sock.recv(1)
                if char == "":
                    break
                msg += char
            except socket.timeout:
                break
        self.logger.debug("Received: {}".format(hexdump(msg)))
        return msg

    def close(self):
        self.sock.close()
        self.connected = False

    def __del__(self):
        try:
            self.close()

        except socket.error as exc:
            self.logger.error("serial socket already closed")
            pass


class UnixSerialMonitor(SerialMonitor):

    def __init__(self, qemu, filename, instance_id):
        """ Monitors a serial port redirected to a UNIX socket
        :param qemu:
        :param filename:
        :param instance_id:
        :return:
        """
        super(UnixSerialMonitor, self).__init__(qemu, filename, instance_id)
        self.instance_id = instance_id
        self.serial = UnixSerialProtocol(self.instance_id)
        self.serial_thread = None
        self.crashed = False
        self.stop = False
        self.serial.connect()
        self.logger = logging.getLogger("Monitor")
        self.logger.setLevel(logging.WARNING)

    def serial_thread_worker(self):
        self.logger.debug("Loaded")
        while not self.stop:
            if self.serial.is_available():
                self.logger.info("Serial message available")
                msg = self.serial.read()

                if len(msg) > 0:
                    if "Clocksource tsc unstable (delta" not in msg or "Switched to clocksource hpet" not in msg:
                        # Might be a kernel panic...
                        # So store the crash info in a file
                        with open("log/crash_{}".format(self.instance_id), "a") as crash:
                            crash.write("#" * 80)
                            crash.write("\n# NEW CRASH: {}\n".format(msg))
                            crash.write("#" * 80)
                        self.crashed = True

    def begin_monitoring(self):
        self.logger.debug("Begin monitoring")
        self.crashed = False
        self.stop = False

        self.serial_thread = threading.Thread(target=self.serial_thread_worker)
        self.serial_thread.setDaemon(True)
        self.serial_thread.start()

    def monitor(self, title):
        self.stop = True
        self.serial_thread.join()

        if self.crashed:
            self.logger.info("Crash detected!")
            log_output = "Monitor detected crash"
            to_write = "{}\n{}\n{}\n".format(title, log_output, config.DELIMITER)
            with open(self.filename, "a") as log_file:
                log_file.write(to_write)

        return True
