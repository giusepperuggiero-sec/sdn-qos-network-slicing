"""Service-based QoS slicing controller routing UDP:9999 video onto the 10 Mbps Upper Slice."""

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
    default_port_map,
    handle_reactive_packet_in,
    install_service_slicing_rules,
    install_table_miss,
)


class RyuController(app_manager.RyuApp):
    """Prioritize streaming video (UDP:9999) over S2 while forwarding general traffic via S3."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.mac_to_port: dict[int, dict[str, int]] = {}
        self.port_map = default_port_map()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev) -> None:
        datapath = ev.msg.datapath
        self.logger.info(f"[SETUP] Configuring service slicing rules for dpid={datapath.id}")
        install_table_miss(datapath)
        install_service_slicing_rules(datapath, self.port_map)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev) -> None:
        handle_reactive_packet_in(
            msg=ev.msg,
            packet_cls=packet.Packet,
            ethernet_cls=ethernet.ethernet,
            mac_to_port=self.mac_to_port,
            port_map=self.port_map,
            logger=self.logger,
            drop_arp=False,
            idle_timeout=10,
        )
