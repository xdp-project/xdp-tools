import subprocess
import os
import signal

import unittest
from scapy.all import (Ether, Packet, IP, IPv6, Raw,
                       UDP, TCP, IPv6ExtHdrRouting)

from xdp_test_harness.xdp_case import XDPCase, usingCustomLoader
from xdp_test_harness.utils import XDPFlag

from . common import Base, XDP_FILTER, get_mode_string


class ManyAddresses(Base):
    def format_number(self, number,
                      delimiter, format_string,
                      part_size, parts_amount):
        splitted = []

        while number > 0:
            splitted.append(int(number % (1 << part_size)))
            number = number >> part_size

        assert(len(splitted) <= parts_amount)
        if (len(splitted) < parts_amount):
            splitted += [0] * (parts_amount - len(splitted))

        splitted.reverse()

        return delimiter.join(format(s, format_string) for s in splitted)

    def generate_addresses(self,
                           delimiter, format_string, parts_amount, full_size):
        AMOUNT = 257

        bits = parts_amount * full_size

        for gen_number in range(0, (1 << bits) - 1, int((1 << bits) / AMOUNT)):
            yield self.format_number(gen_number, delimiter,
                                     format_string, parts_amount, full_size)

    def filter_addresses(self, name,
                         delimiter, format_string, parts_amount, full_size):
        summed = 0
        for address in self.generate_addresses(delimiter, format_string,
                                               parts_amount, full_size):
            summed += 1
            subprocess.run([XDP_FILTER, name, address, "--mode", "dst"])

        output = subprocess.check_output([XDP_FILTER, "status"])
        # Each address is on a separate line.
        self.assertGreaterEqual(len(output.splitlines()), summed)

    def get_invalid_address(self, name,
                            delimiter, format_string,
                            parts_amount, full_size):
        """
        Try to add addresses to xdp-filter,
        return address that does not get added.
        """

        last_length = subprocess.check_output([XDP_FILTER, "status"])
        for address in self.generate_addresses(delimiter, format_string,
                                               parts_amount, full_size):
            new_length = subprocess.check_output(
                [XDP_FILTER, name, address, "--mode", "dst", "--status"])

            if new_length == last_length:
                return address
            last_length = new_length

        return None

    def test_ip_arrive(self):
        missing = self.get_invalid_address("ip", ".", "d", 8, 4)

        if missing is None:
            return

        to_send = self.generate_default_packets(dst_inet=missing)
        res = self.send_packets(to_send)
        self.not_arrived(to_send, res)

    def test_ether_arrive(self):
        missing = self.get_invalid_address("ether", ":", "02x", 8, 6)

        if missing is None:
            return

        to_send = self.generate_default_packets(dst_ether=missing)
        res = self.send_packets(to_send)
        self.not_arrived(to_send, res)

    def test_port_arrive(self):
        missing = self.get_invalid_address("port", "", "d", 16, 1)

        if missing is None:
            return

        to_send = self.generate_default_packets(dst_port=missing)
        res = self.send_packets(to_send)
        self.not_arrived(to_send, res)

    def test_ip_status(self):
        self.filter_addresses("ip", ".", "d", 8, 4)

    def test_port_status(self):
        self.filter_addresses("port", "", "d", 16, 1)

    def test_ether_status(self):
        self.filter_addresses("ether", ":", "02x", 8, 6)


class ManyAddressesInverted(ManyAddresses):
    def setUp(self):
        subprocess.run([
            XDP_FILTER, "load",
            "--policy", "deny",
            self.get_contexts().get_local_main().iface,
            "--mode", get_mode_string(
                self.get_contexts().get_local_main().xdp_mode
            )
        ])

    arrived = Base.not_arrived
    not_arrived = Base.arrived
