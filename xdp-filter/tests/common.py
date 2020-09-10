import os
import subprocess

from xdp_test_harness.xdp_case import XDPCase, usingCustomLoader
from xdp_test_harness.utils import XDPFlag


XDP_FILTER = os.environ.get("XDP_FILTER", "xdp-filter")


def get_mode_string(xdp_mode: XDPFlag):
    if xdp_mode == XDPFlag.SKB_MODE:
        return "skb"
    if xdp_mode == XDPFlag.DRV_MODE:
        return "native"
    if xdp_mode == XDPFlag.HW_MODE:
        return "hw"
    return None


@usingCustomLoader
class Base(XDPCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.src_port = 60001
        cls.dst_port = 60002
        cls.to_send = cls.generate_default_packets(
            src_port=cls.src_port, dst_port=cls.dst_port)
        cls.to_send6 = cls.generate_default_packets(
            src_port=cls.src_port, dst_port=cls.dst_port, use_inet6=True)

    def arrived(self, packets, result):
        self.assertPacketsIn(packets, result.captured_local)
        for i in result.captured_remote:
            self.assertPacketContainerEmpty(i)

    def not_arrived(self, packets, result):
        self.assertPacketsNotIn(packets, result.captured_local)
        for i in result.captured_remote:
            self.assertPacketContainerEmpty(i)

    def setUp(self):
        subprocess.check_output([
            XDP_FILTER, "load",
            self.get_contexts().get_local_main().iface,
            "--mode", get_mode_string(
                self.get_contexts().get_local_main().xdp_mode
            )
        ], stderr=subprocess.STDOUT)

    def tearDown(self):
        subprocess.check_output([
            XDP_FILTER, "unload", "--all"
        ], stderr=subprocess.STDOUT)
