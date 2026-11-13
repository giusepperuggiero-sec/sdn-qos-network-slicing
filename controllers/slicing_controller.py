"""Topology-based SDN slicing controller isolating H1<->H3 (10M) and H2<->H4 (1M)."""

from __future__ import annotations

from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import ethernet, packet
from ryu.ofproto import ofproto_v1_3

from common.openflow_utils import (
    ARP_ETH_TYPE,
    DEFAULT_HOSTS,
    IPV4_ETH_TYPE,
    add_flow,
    default_port_map,
    handle_reactive_packet_in,
    install_table_miss,
)


class RyuSlicing(app_manager.RyuApp):
    """Enforce strict L2/ARP isolation between upper (H1<->H3) and lower (H2<->H4) slices."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.mac_to_port: dict[int, dict[str, int]] = {}
        self.port_map = default_port_map()
        self.h1 = DEFAULT_HOSTS["h1"]["mac"]
        self.h2 = DEFAULT_HOSTS["h2"]["mac"]
        self.h3 = DEFAULT_HOSTS["h3"]["mac"]
        self.h4 = DEFAULT_HOSTS["h4"]["mac"]
        self.ip_h1 = DEFAULT_HOSTS["h1"]["ip"]
        self.ip_h2 = DEFAULT_HOSTS["h2"]["ip"]
        self.ip_h3 = DEFAULT_HOSTS["h3"]["ip"]
        self.ip_h4 = DEFAULT_HOSTS["h4"]["ip"]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev) -> None:
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        dpid = datapath.id

        self.logger.info(f"[SETUP] Configuring topology slicing rules for dpid={dpid}")
        install_table_miss(datapath)

        if dpid == 1:
            ip_rules = [
                (self.h1, self.h3, 3),
                (self.h3, self.h1, 1),
                (self.h2, self.h4, 4),
                (self.h4, self.h2, 2),
            ]
            arp_rules = [(self.ip_h1, 1), (self.ip_h2, 2), (self.ip_h3, 3), (self.ip_h4, 4)]
        elif dpid == 2:
            ip_rules = [(self.h1, self.h3, 2), (self.h3, self.h1, 1)]
            arp_rules = [(self.ip_h1, 1), (self.ip_h3, 2)]
        elif dpid == 3:
            ip_rules = [(self.h2, self.h4, 2), (self.h4, self.h2, 1)]
            arp_rules = [(self.ip_h2, 1), (self.ip_h4, 2)]
        elif dpid == 4:
            ip_rules = [
                (self.h1, self.h3, 3),
                (self.h3, self.h1, 1),
                (self.h2, self.h4, 4),
                (self.h4, self.h2, 2),
            ]
            arp_rules = [(self.ip_h1, 1), (self.ip_h2, 2), (self.ip_h3, 3), (self.ip_h4, 4)]
        else:
            ip_rules, arp_rules = [], []

        for src_mac, dst_mac, out_port in ip_rules:
            add_flow(
                datapath,
                priority=100,
                match=parser.OFPMatch(eth_type=IPV4_ETH_TYPE, eth_src=src_mac, eth_dst=dst_mac),
                actions=[parser.OFPActionOutput(out_port)],
            )

        for target_ip, out_port in arp_rules:
            add_flow(
                datapath,
                priority=150,
                match=parser.OFPMatch(eth_type=ARP_ETH_TYPE, arp_tpa=target_ip),
                actions=[parser.OFPActionOutput(out_port)],
            )

        # Explicit low-priority drop for unauthorized cross-slice IPv4 traffic
        add_flow(datapath, priority=1, match=parser.OFPMatch(eth_type=IPV4_ETH_TYPE), actions=[])

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev) -> None:
        handle_reactive_packet_in(
            msg=ev.msg,
            packet_cls=packet.Packet,
            ethernet_cls=ethernet.ethernet,
            mac_to_port=self.mac_to_port,
            port_map=self.port_map,
            logger=self.logger,
            drop_arp=True,
            idle_timeout=30,
        )
