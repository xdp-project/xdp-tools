import subprocess
import os
import signal

import unittest
import scapy
from scapy.all import (Ether, Packet, IP, IPv6, Raw,
                       UDP, TCP, IPv6ExtHdrRouting)

from xdp_test_harness.xdp_case import XDPCase, usingCustomLoader
from xdp_test_harness.utils import XDPFlag

from . common import XDP_FILTER, Base, get_mode_string


@usingCustomLoader
class LoadUnload(XDPCase):
    def setUp(self):
        self.msg = "WARNING: All tests that follow will likely provide false result.\n"

    def run_wrap(self, cmd):
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.msg += "command: '" + str(cmd) + "'\n"
        self.msg += "stdout: '" + r.stdout.decode().strip() + "'\n"
        if r.stderr is not None:
            self.msg += "stderr: '" + r.stderr.decode().strip() + "'\n"
        self.msg += "\n"
        return r.returncode == 0

    def load(self, mode=None):
        return self.run_wrap([
            XDP_FILTER, "load",
            self.get_contexts().get_local_main().iface,
            "--verbose",
            "--mode", get_mode_string(
                mode if mode else self.get_contexts().get_local_main().xdp_mode
            )
        ])

    def unload(self):
        return self.run_wrap([
            XDP_FILTER, "unload",
            self.get_contexts().get_local_main().iface,
            "--verbose"
        ])

    def test_load_once(self):
        self.assertFalse(self.unload(), self.msg)
        self.assertTrue(self.load(), self.msg)
        self.assertTrue(self.unload(), self.msg)
        self.assertFalse(self.unload(), self.msg)

    def test_load_twice(self):
        self.assertFalse(self.unload(), self.msg)
        self.assertTrue(self.load(), self.msg)
        self.assertFalse(self.load(), self.msg)
        self.assertTrue(self.unload(), self.msg)
        self.assertFalse(self.unload(), self.msg)

    def test_load_hw(self):
        self.assertFalse(self.unload(), self.msg)
        self.load(mode=XDPFlag.HW_MODE), self.msg
        self.unload(), self.msg
        self.assertFalse(self.unload(), self.msg)


class DirectBase:
    def drop_generic(self, address, target, use_inet6=False):
        to_send = self.to_send6 if use_inet6 else self.to_send

        self.arrived(to_send, self.send_packets(to_send))

        subprocess.run([XDP_FILTER, target, address,
                        "--mode", self.get_mode()])

        self.not_arrived(to_send, self.send_packets(to_send))

        subprocess.run([XDP_FILTER, target, address,
                        "--mode", self.get_mode(),
                        "--remove"])

        self.arrived(to_send, self.send_packets(to_send))

    def test_none_specified(self):
        self.arrived(self.to_send, self.send_packets(self.to_send))

    def test_ether(self):
        self.drop_generic(self.get_device().ether, "ether")

    def test_ip(self):
        self.drop_generic(self.get_device().inet, "ip")

    def test_port(self):
        self.drop_generic(str(self.get_port()), "port")

    @unittest.skipIf(XDPCase.get_contexts().get_local_main().inet6 is None or
                     XDPCase.get_contexts().get_remote_main().inet6 is None,
                     "no inet6 address available")
    def test_ipv6(self):
        self.drop_generic(self.get_device().inet6, "ip", use_inet6=True)


class BaseSrc:
    def get_device(self):
        return self.get_contexts().get_remote_main()

    def get_port(self):
        return self.src_port

    def get_mode(self):
        return "src"


class BaseDst:
    def get_device(self):
        return self.get_contexts().get_local_main()

    def get_port(self):
        return self.dst_port

    def get_mode(self):
        return "dst"


class BaseInvert:
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


class DirectDropSrc(Base, DirectBase, BaseSrc):
    pass


class DirectPassSrc(Base, DirectBase, BaseSrc, BaseInvert):
    pass


class DirectDropDst(Base, DirectBase, BaseDst):
    pass


class DirectPassDst(Base, DirectBase, BaseDst, BaseInvert):
    pass


class IPv6ExtensionHeader(Base):
    def generic(self, extensions):
        packets = [Ether() /
                   IPv6() / extensions /
                   UDP(dport=55555)] * 5

        self.arrived(packets, self.send_packets(packets))

        subprocess.run([XDP_FILTER,
                        "port", "55555",
                        "--mode", "dst"])
        self.not_arrived(packets, self.send_packets(packets))

        subprocess.run([XDP_FILTER,
                        "port", "55555",
                        "--mode", "dst",
                        "--remove"])
        self.arrived(packets, self.send_packets(packets))

    def test_routing(self):
        self.generic(scapy.layers.inet6.IPv6ExtHdrRouting())

    def test_hop_by_hop(self):
        self.generic(scapy.layers.inet6.IPv6ExtHdrHopByHop())

    def test_destination_options(self):
        self.generic(scapy.layers.inet6.IPv6ExtHdrDestOpt())

    def test_fragment(self):
        self.generic(scapy.layers.inet6.IPv6ExtHdrFragment())


class IPv4ToIPv6Mapping(Base):
    def setUp(self):
        super().setUp()

        inet = self.get_contexts().get_local_main().inet

        self.address_explicit = "::ffff:" + inet

        inet6_split = [format(int(i), "02x") for i in inet.split(".")]
        self.address_converted = "::ffff:" + \
            inet6_split[0] + inet6_split[1] + ":" + \
            inet6_split[2] + inet6_split[3]

        self.packets = self.generate_default_packets(
            dst_inet=self.address_explicit, use_inet6=True)
        self.packets += self.generate_default_packets(
            dst_inet=self.address_converted, use_inet6=True)

    def test_filter_explicit_address(self):
        self.arrived(self.packets, self.send_packets(self.packets))

        subprocess.run([XDP_FILTER,
                        "ip", self.address_explicit,
                        "--mode", "dst"])
        self.not_arrived(self.packets, self.send_packets(self.packets))

        subprocess.run([XDP_FILTER,
                        "ip", self.address_explicit,
                        "--mode", "dst",
                        "--remove"])
        self.arrived(self.packets, self.send_packets(self.packets))

    def test_filter_converted_address(self):
        self.arrived(self.packets, self.send_packets(self.packets))

        subprocess.run([XDP_FILTER,
                        "ip", self.address_converted,
                        "--mode", "dst"])
        self.not_arrived(self.packets, self.send_packets(self.packets))

        subprocess.run([XDP_FILTER,
                        "ip", self.address_converted,
                        "--mode", "dst",
                        "--remove"])
        self.arrived(self.packets, self.send_packets(self.packets))


class Status(Base):
    def setUp(self):
        pass

    def load(self, features):
        return subprocess.run([
            XDP_FILTER, "load",
            self.get_contexts().get_local_main().iface,
            "--mode", get_mode_string(
                self.get_contexts().get_local_main().xdp_mode
            ),
            "--features", features,
        ])

    def get_status(self):
        return subprocess.run(
            [XDP_FILTER, "status"], capture_output=True
        ).stdout.decode()

    def test_ethernet_feature(self):
        self.load("ethernet")
        self.check_status("ether", self.get_contexts().get_local_main().ether)

    def test_ipv4_feature(self):
        self.load("ipv4")
        self.check_status("ip", self.get_contexts().get_local_main().inet)

    def test_udp_feature(self):
        self.load("udp")
        self.check_status("port", str(self.dst_port))

    def test_all_features(self):
        self.load("all")
        self.check_status("ether", self.get_contexts().get_local_main().ether)
        self.check_status("ip", self.get_contexts().get_local_main().inet)
        self.check_status("port", str(self.dst_port))

    def check_status(self, subcommand, address):
        self.assertEqual(self.get_status().find(address), -1)

        subprocess.run([XDP_FILTER, subcommand, address])
        self.assertNotEqual(self.get_status().find(address), -1)

        subprocess.run([XDP_FILTER, subcommand, address, "--remove"])
        self.assertEqual(self.get_status().find(address), -1)
