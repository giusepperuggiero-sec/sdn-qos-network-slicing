"""Service-based QoS slicing controller with thread-safe Prometheus telemetry export."""

from __future__ import annotations

from pathlib import Path
import sys
import threading

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import ethernet, packet
from ryu.ofproto import ofproto_v1_3

from common.metrics_server import MetricsServer, MetricsStore
from common.openflow_utils import (
    STATS_REQUEST_INTERVAL,
    default_port_map,
    handle_reactive_packet_in,
    install_service_slicing_rules,
    install_table_miss,
)


class DashboardController(app_manager.RyuApp):
    """Expose OpenFlow 1.3 port counters on Prometheus `/metrics` alongside service slicing."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.mac_to_port: dict[int, dict[str, int]] = {}
        self.port_map = default_port_map()
        self.datapaths: dict[int, object] = {}
        self._dp_lock = threading.Lock()
        self._stop_event = threading.Event()
        self.metrics_store = MetricsStore()
        self.metrics_server = MetricsServer(store=self.metrics_store)
        self.metrics_server.start()
        self.monitor_thread = threading.Thread(target=self.monitor, daemon=True)
        self.monitor_thread.start()

    def monitor(self) -> None:
        """Periodically poll active switches for OFPPortStats."""
        while not self._stop_event.wait(STATS_REQUEST_INTERVAL):
            with self._dp_lock:
                active_dps = list(self.datapaths.values())
            for dp in active_dps:
                self.request_stats(dp)

    def request_stats(self, datapath) -> None:
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev) -> None:
        datapath = ev.datapath
        dpid = datapath.id
        if ev.state == MAIN_DISPATCHER:
            with self._dp_lock:
                if dpid not in self.datapaths:
                    self.logger.info(f"[MONITOR] Registering datapath dpid={dpid}")
                    self.datapaths[dpid] = datapath
        elif ev.state == DEAD_DISPATCHER:
            with self._dp_lock:
                if self.datapaths.pop(dpid, None) is not None:
                    self.logger.info(f"[MONITOR] Unregistering datapath dpid={dpid}")
            self.metrics_store.remove_dpid(dpid)
            self.mac_to_port.pop(dpid, None)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev) -> None:
        dpid = ev.msg.datapath.id
        stats_by_port = {
            stat.port_no: {
                "rx_packets": stat.rx_packets,
                "tx_packets": stat.tx_packets,
                "rx_bytes": stat.rx_bytes,
                "tx_bytes": stat.tx_bytes,
                "rx_errors": stat.rx_errors,
                "tx_errors": stat.tx_errors,
            }
            for stat in ev.msg.body
        }
        self.metrics_store.update_dpid(dpid, stats_by_port)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev) -> None:
        datapath = ev.msg.datapath
        self.logger.info(f"[SETUP] Configuring dashboard service slicing for dpid={datapath.id}")
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

    def close(self) -> None:
        self._stop_event.set()
        self.metrics_server.stop()
        super().close()
