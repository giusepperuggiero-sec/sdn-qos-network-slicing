"""Adaptive QoS traffic-classification controller combining statistical flow inspection with Prometheus telemetry."""

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
    DEFAULT_HOSTS,
    IPV4_ETH_TYPE,
    IP_PROTO_UDP,
    POLL_INTERVAL,
    STATIC_SLICE_PRIORITY,
    VIDEO_MIN_AVG_PKT,
    VIDEO_MIN_BPS,
    VIDEO_MIN_PPS,
    VIDEO_PRIORITY,
    add_flow,
    compute_flow_metrics,
    default_port_map,
    get_match_field,
    handle_reactive_packet_in,
    install_table_miss,
    is_video_flow,
    resolve_adaptive_out_port,
)


class TrafficController(app_manager.RyuApp):
    """Classify dynamic flows via OpenFlow FlowStats and promote video streams to Upper Slice S2."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.mac_to_port: dict[int, dict[str, int]] = {}
        self.port_map = default_port_map()
        self.flow_stats: dict[int, list] = {}
        self.datapaths: dict[int, object] = {}
        self._dp_lock = threading.Lock()
        self._stop_event = threading.Event()

        self.POLL_INTERVAL = POLL_INTERVAL
        self.VIDEO_MIN_AVG_PKT = VIDEO_MIN_AVG_PKT
        self.VIDEO_MIN_PPS = VIDEO_MIN_PPS
        self.VIDEO_MIN_BPS = VIDEO_MIN_BPS
        self.VIDEO_PRIORITY = VIDEO_PRIORITY

        self.metrics_store = MetricsStore()
        self.metrics_server = MetricsServer(store=self.metrics_store)
        self.metrics_server.start()

        self.stats_collector_thread = threading.Thread(
            target=self._stats_collector,
            daemon=True,
        )
        self.stats_collector_thread.start()

    def install_static_slice_rules(self, datapath) -> None:
        """Install high-priority static slice paths for baseline hosts (H1<->H3 UP, H2<->H4 DW)."""
        parser = datapath.ofproto_parser
        dpid = datapath.id
        mac_h1 = DEFAULT_HOSTS["h1"]["mac"]
        mac_h2 = DEFAULT_HOSTS["h2"]["mac"]
        mac_h3 = DEFAULT_HOSTS["h3"]["mac"]
        mac_h4 = DEFAULT_HOSTS["h4"]["mac"]

        if dpid == 1:
            add_flow(
                datapath,
                priority=STATIC_SLICE_PRIORITY,
                match=parser.OFPMatch(in_port=1, eth_dst=mac_h3),
                actions=[parser.OFPActionOutput(self.port_map[dpid]["to_s2"])],
            )
            add_flow(
                datapath,
                priority=STATIC_SLICE_PRIORITY,
                match=parser.OFPMatch(in_port=2, eth_dst=mac_h4),
                actions=[parser.OFPActionOutput(self.port_map[dpid]["to_s3"])],
            )
        elif dpid in (2, 3):
            p_s1 = self.port_map[dpid]["to_s1"]
            p_s4 = self.port_map[dpid]["to_s4"]
            for in_p, out_p in ((p_s1, p_s4), (p_s4, p_s1)):
                add_flow(
                    datapath,
                    priority=STATIC_SLICE_PRIORITY,
                    match=parser.OFPMatch(in_port=in_p),
                    actions=[parser.OFPActionOutput(out_p)],
                )
        elif dpid == 4:
            add_flow(
                datapath,
                priority=STATIC_SLICE_PRIORITY,
                match=parser.OFPMatch(in_port=3, eth_dst=mac_h1),
                actions=[parser.OFPActionOutput(self.port_map[dpid]["to_s2"])],
            )
            add_flow(
                datapath,
                priority=STATIC_SLICE_PRIORITY,
                match=parser.OFPMatch(in_port=4, eth_dst=mac_h2),
                actions=[parser.OFPActionOutput(self.port_map[dpid]["to_s3"])],
            )

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev) -> None:
        datapath = ev.msg.datapath
        dpid = datapath.id
        self.logger.info(f"[SETUP] Configuring adaptive QoS controller on dpid={dpid}")
        self.mac_to_port.setdefault(dpid, {})
        install_table_miss(datapath)
        self.install_static_slice_rules(datapath)

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

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev) -> None:
        datapath = ev.datapath
        dpid = datapath.id
        if ev.state == MAIN_DISPATCHER:
            with self._dp_lock:
                self.datapaths[dpid] = datapath
        elif ev.state == DEAD_DISPATCHER:
            with self._dp_lock:
                self.datapaths.pop(dpid, None)
            self.flow_stats.pop(dpid, None)
            self.metrics_store.remove_dpid(dpid)
            self.mac_to_port.pop(dpid, None)
            self.logger.info("Switch disconnected: dpid=%s", dpid)

    def _stats_collector(self) -> None:
        while not self._stop_event.wait(self.POLL_INTERVAL):
            with self._dp_lock:
                active_dps = list(self.datapaths.values())
            for datapath in active_dps:
                self._request_stats(datapath)

    def _request_stats(self, datapath) -> None:
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        datapath.send_msg(
            parser.OFPFlowStatsRequest(datapath, 0, ofp.OFPTT_ALL, ofp.OFPP_ANY, ofp.OFPG_ANY)
        )
        datapath.send_msg(parser.OFPPortStatsRequest(datapath, 0, ofp.OFPP_ANY))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev) -> None:
        datapath = ev.msg.datapath
        dpid = datapath.id
        parser = datapath.ofproto_parser
        body = ev.msg.body
        self.flow_stats[dpid] = body

        for stat in body:
            # Skip table-miss (0), already-promoted adaptive flows (>=200), and static slice rules
            if stat.priority <= 0 or stat.priority >= self.VIDEO_PRIORITY:
                continue

            metrics = compute_flow_metrics(
                packet_count=stat.packet_count,
                byte_count=stat.byte_count,
                duration_sec=stat.duration_sec,
                duration_nsec=getattr(stat, "duration_nsec", 0),
            )
            if metrics is None:
                continue

            _, avg_pkt, pps, bps = metrics
            video_detected = is_video_flow(
                avg_pkt,
                pps,
                bps,
                min_avg_pkt=self.VIDEO_MIN_AVG_PKT,
                min_pps=self.VIDEO_MIN_PPS,
                min_bps=self.VIDEO_MIN_BPS,
            )
            self.logger.info(
                "[CLASSIFICATION] dpid=%s | pps=%.4f | avg_pkt=%.2f B | bitrate=%.2f kbps | video=%s",
                dpid,
                pps,
                avg_pkt,
                bps / 1000.0,
                video_detected,
            )
            if not video_detected:
                continue

            in_port = get_match_field(stat.match, "in_port")
            eth_src = get_match_field(stat.match, "eth_src")
            eth_dst = get_match_field(stat.match, "eth_dst")
            udp_dst = get_match_field(stat.match, "udp_dst")

            out_port = resolve_adaptive_out_port(
                dpid=dpid,
                in_port=in_port,
                eth_dst=eth_dst,
                port_map=self.port_map,
                mac_to_port=self.mac_to_port,
            )
            if out_port is None:
                continue

            match_kwargs: dict[str, int | str] = {}
            if in_port is not None:
                match_kwargs["in_port"] = in_port
            if eth_src is not None:
                match_kwargs["eth_src"] = eth_src
            if eth_dst is not None:
                match_kwargs["eth_dst"] = eth_dst
            if udp_dst is not None:
                match_kwargs["eth_type"] = IPV4_ETH_TYPE
                match_kwargs["ip_proto"] = IP_PROTO_UDP
                match_kwargs["udp_dst"] = udp_dst

            if not match_kwargs:
                continue

            add_flow(
                datapath,
                priority=self.VIDEO_PRIORITY,
                match=parser.OFPMatch(**match_kwargs),
                actions=[parser.OFPActionOutput(out_port)],
                idle_timeout=600,
            )
            self.logger.info(
                "[FLOW MOD] Promoted high-rate flow (prio=%s) on dpid=%s -> port %s",
                self.VIDEO_PRIORITY,
                dpid,
                out_port,
            )

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
                "duration_sec": stat.duration_sec,
            }
            for stat in ev.msg.body
        }
        self.metrics_store.update_dpid(dpid, stats_by_port)

    def close(self) -> None:
        self._stop_event.set()
        self.metrics_server.stop()
        super().close()
