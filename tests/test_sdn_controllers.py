"""Unit tests for SDN OpenFlow 1.3 helpers, Prometheus exporter, and controller handlers."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import sys
import types
import unittest
import urllib.error
import urllib.request

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from common.metrics_server import (
    MetricsServer,
    MetricsStore,
    escape_prometheus_label,
    format_prometheus_metrics,
)
from common.openflow_utils import (
    DEFAULT_HOSTS,
    DEFAULT_OFP_NO_BUFFER,
    add_flow,
    compute_flow_metrics,
    default_port_map,
    get_controlled_flood_ports,
    is_video_flow,
    resolve_adaptive_out_port,
    send_packet_out,
)


def _install_mock_ryu() -> None:
    """Install lightweight Ryu stub modules when running tests outside Linux/Mininet."""
    if "ryu.base.app_manager" in sys.modules:
        return

    ryu = types.ModuleType("ryu")
    base = types.ModuleType("ryu.base")
    app_manager = types.ModuleType("ryu.base.app_manager")
    controller = types.ModuleType("ryu.controller")
    ofp_event = types.ModuleType("ryu.controller.ofp_event")
    handler = types.ModuleType("ryu.controller.handler")
    ofproto = types.ModuleType("ryu.ofproto")
    ofproto_v1_3 = types.ModuleType("ryu.ofproto.ofproto_v1_3")
    lib = types.ModuleType("ryu.lib")
    packet_mod = types.ModuleType("ryu.lib.packet")
    ethernet_mod = types.ModuleType("ryu.lib.packet.ethernet")
    packet_sub = types.ModuleType("ryu.lib.packet.packet")

    class DummyLogger:
        def info(self, *args, **kwargs):
            pass

    class DummyRyuApp:
        def __init__(self, *args, **kwargs):
            self.logger = DummyLogger()

        def close(self):
            pass

    app_manager.RyuApp = DummyRyuApp
    ofp_event.EventOFPSwitchFeatures = object
    ofp_event.EventOFPPacketIn = object
    ofp_event.EventOFPStateChange = object
    ofp_event.EventOFPFlowStatsReply = object
    ofp_event.EventOFPPortStatsReply = object

    handler.CONFIG_DISPATCHER = 1
    handler.MAIN_DISPATCHER = 2
    handler.DEAD_DISPATCHER = 3
    handler.set_ev_cls = lambda *args, **kwargs: (lambda fn: fn)

    ofproto_v1_3.OFP_VERSION = 0x04

    class DummyEthernet:
        def __init__(self, src="00:00:00:00:00:01", dst="00:00:00:00:00:03", ethertype=0x0800):
            self.src = src
            self.dst = dst
            self.ethertype = ethertype

    class DummyPacket:
        def __init__(self, data):
            self.data = data

        def get_protocol(self, cls):
            return self.data if isinstance(self.data, DummyEthernet) else None

    ethernet_mod.ethernet = DummyEthernet
    packet_sub.Packet = DummyPacket

    for name, mod in [
        ("ryu", ryu),
        ("ryu.base", base),
        ("ryu.base.app_manager", app_manager),
        ("ryu.controller", controller),
        ("ryu.controller.ofp_event", ofp_event),
        ("ryu.controller.handler", handler),
        ("ryu.ofproto", ofproto),
        ("ryu.ofproto.ofproto_v1_3", ofproto_v1_3),
        ("ryu.lib", lib),
        ("ryu.lib.packet", packet_mod),
        ("ryu.lib.packet.ethernet", ethernet_mod),
        ("ryu.lib.packet.packet", packet_sub),
    ]:
        sys.modules[name] = mod


class _MockOfproto:
    OFPIT_APPLY_ACTIONS = 4
    OFPP_CONTROLLER = 0xFFFFFFFD
    OFPCML_NO_BUFFER = 0xFFFF
    OFPP_ANY = 0xFFFFFFFF
    OFPG_ANY = 0xFFFFFFFF
    OFPTT_ALL = 0xFF
    OFP_NO_BUFFER = DEFAULT_OFP_NO_BUFFER


class _MockParser:
    @staticmethod
    def OFPMatch(**kwargs):
        return dict(kwargs)

    @staticmethod
    def OFPActionOutput(port, max_len=None):
        return ("OUTPUT", port, max_len)

    @staticmethod
    def OFPInstructionActions(inst_type, actions):
        return ("INST", inst_type, list(actions))

    @staticmethod
    def OFPFlowMod(**kwargs):
        return ("FLOW_MOD", kwargs)

    @staticmethod
    def OFPPacketOut(**kwargs):
        return ("PACKET_OUT", kwargs)

    @staticmethod
    def OFPFlowStatsRequest(*args):
        return ("FLOW_STATS_REQ", args)

    @staticmethod
    def OFPPortStatsRequest(*args):
        return ("PORT_STATS_REQ", args)


class _MockDatapath:
    def __init__(self, dpid: int) -> None:
        self.id = dpid
        self.ofproto = _MockOfproto()
        self.ofproto_parser = _MockParser()
        self.sent: list[tuple] = []

    def send_msg(self, msg: tuple) -> None:
        self.sent.append(msg)


@dataclass
class _MockFlowStat:
    priority: int
    packet_count: int
    byte_count: int
    duration_sec: int
    duration_nsec: int
    match: dict


class OpenFlowUtilsTests(unittest.TestCase):
    def test_buffer_id_semantics_on_flow_mod_and_packet_out(self) -> None:
        dp = _MockDatapath(1)
        add_flow(dp, priority=100, match={"in_port": 1}, actions=[("OUTPUT", 3)], buffer_id=DEFAULT_OFP_NO_BUFFER)
        _, fm_kwargs = dp.sent.pop()
        self.assertNotIn("buffer_id", fm_kwargs)

        add_flow(dp, priority=100, match={"in_port": 1}, actions=[("OUTPUT", 3)], buffer_id=0)
        _, fm_kwargs = dp.sent.pop()
        self.assertEqual(fm_kwargs["buffer_id"], 0)

        send_packet_out(dp, buffer_id=DEFAULT_OFP_NO_BUFFER, in_port=1, actions=[("OUTPUT", 3)], raw_data=b"abc")
        _, po_kwargs = dp.sent.pop()
        self.assertEqual(po_kwargs["data"], b"abc")

        send_packet_out(dp, buffer_id=42, in_port=1, actions=[("OUTPUT", 3)], raw_data=b"abc")
        _, po_kwargs = dp.sent.pop()
        self.assertIsNone(po_kwargs["data"])

    def test_controlled_flood_avoids_diamond_loops(self) -> None:
        pmap = default_port_map()
        # S1 excludes in_port=1 and never floods onto upper slice S2 (port 3)
        self.assertEqual(get_controlled_flood_ports(1, 1, pmap), [2, 4])
        # S4 excludes in_port=2 (from S3) and delivers to hosts [3, 4], never onto S2 (port 1)
        self.assertEqual(get_controlled_flood_ports(4, 2, pmap), [3, 4])
        # S2 transit only forwards opposite port
        self.assertEqual(get_controlled_flood_ports(2, 1, pmap), [2])

    def test_flow_metrics_guard_against_duration_nsec_zero_spike(self) -> None:
        # 1 packet received at t=0.05s must be skipped (previously divided by 1e-6 -> 100+ Mbps spike!)
        self.assertIsNone(compute_flow_metrics(1, 1450, duration_sec=0, duration_nsec=50_000_000))
        metrics = compute_flow_metrics(1293, 1293 * 1450, duration_sec=1, duration_nsec=0)
        self.assertIsNotNone(metrics)
        dur, avg_pkt, pps, bps = metrics
        self.assertAlmostEqual(dur, 1.0)
        self.assertAlmostEqual(avg_pkt, 1450.0)
        self.assertGreater(pps, 1000)
        self.assertTrue(is_video_flow(avg_pkt, pps, bps))

    def test_resolve_adaptive_out_port_prevents_s4_to_s2_loop(self) -> None:
        pmap = default_port_map()
        mac_h4 = DEFAULT_HOSTS["h4"]["mac"]
        mac_table = {4: {mac_h4: 4}}

        # At S1 ingress host port 1 -> promote onto Upper Slice S2 (port 3)
        self.assertEqual(resolve_adaptive_out_port(1, 1, mac_h4, pmap, mac_table), 3)
        # At S2 transit from S1 -> forward to S4 (port 2)
        self.assertEqual(resolve_adaptive_out_port(2, 1, mac_h4, pmap, mac_table), 2)
        # At S4 arriving from S2 (in_port=1) -> MUST deliver to host port 4, NEVER loop back to S2
        self.assertEqual(resolve_adaptive_out_port(4, 1, mac_h4, pmap, mac_table), 4)
        # Unknown MAC arriving from S2 at S4 -> return None rather than looping back to S2
        self.assertIsNone(resolve_adaptive_out_port(4, 1, "aa:bb:cc:dd:ee:ff", pmap, mac_table))


class PrometheusExporterTests(unittest.TestCase):
    def test_prometheus_label_escaping_and_http_endpoint(self) -> None:
        self.assertEqual(escape_prometheus_label('1"bad\n'), '1\\"bad\\n')
        store = MetricsStore()
        store.update_dpid(1, {3: {"tx_bytes": 123456, "rx_bytes": 789}})
        text = format_prometheus_metrics(store.snapshot())
        self.assertIn('ofp_port_tx_bytes_total{dpid="1",port="3"} 123456', text)

        server = MetricsServer(port=0, host="127.0.0.1", store=store)
        server.start()
        try:
            self.assertTrue(server.ready.wait(timeout=3))
            self.assertNotEqual(server.port, 0)
            body = urllib.request.urlopen(f"http://127.0.0.1:{server.port}/metrics", timeout=3).read().decode("utf-8")
            self.assertIn('ofp_port_tx_bytes_total{dpid="1",port="3"} 123456', body)
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(f"http://127.0.0.1:{server.port}/health", timeout=3)
            self.assertEqual(ctx.exception.code, 404)
        finally:
            server.stop()


class ControllerHandlerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        _install_mock_ryu()

    def test_traffic_controller_state_change_and_loop_free_flow_promotion(self) -> None:
        from controllers.traffic_controller import TrafficController

        prev_port = os.environ.get("PROMETHEUS_PORT")
        os.environ["PROMETHEUS_PORT"] = "0"
        ctrl = TrafficController()
        try:
            ctrl.metrics_server.ready.wait(timeout=3)
            dp1 = _MockDatapath(1)
            dp4 = _MockDatapath(4)

            # Register S1 and S4 via MAIN_DISPATCHER, confirm CONFIG_DISPATCHER does not fire cleanup
            ctrl._state_change_handler(types.SimpleNamespace(datapath=dp1, state=2))
            ctrl._state_change_handler(types.SimpleNamespace(datapath=dp4, state=2))
            self.assertIn(1, ctrl.datapaths)
            ctrl._state_change_handler(types.SimpleNamespace(datapath=dp1, state=1))  # CONFIG_DISPATCHER ignored
            self.assertIn(1, ctrl.datapaths)

            # Populate learned host MAC for H4 on S4 port 4
            ctrl.mac_to_port[4] = {DEFAULT_HOSTS["h4"]["mac"]: 4}

            # S4 receives FlowStats reply for flow arriving FROM S2 (in_port=1) bound to H4
            stat = _MockFlowStat(
                priority=1,
                packet_count=500,
                byte_count=500 * 1400,
                duration_sec=2,
                duration_nsec=0,
                match={
                    "in_port": 1,
                    "eth_src": DEFAULT_HOSTS["h1"]["mac"],
                    "eth_dst": DEFAULT_HOSTS["h4"]["mac"],
                },
            )
            ctrl._flow_stats_reply_handler(types.SimpleNamespace(msg=types.SimpleNamespace(datapath=dp4, body=[stat])))
            self.assertEqual(len(dp4.sent), 1)
            _, kwargs = dp4.sent[0]
            self.assertEqual(kwargs["priority"], ctrl.VIDEO_PRIORITY)
            # Verified: output port is host port 4, NOT port 1 (to_s2)
            self.assertEqual(kwargs["instructions"][0][2][0][1], 4)

            # Unregister via DEAD_DISPATCHER cleans state cleanly
            ctrl._state_change_handler(types.SimpleNamespace(datapath=dp4, state=3))
            self.assertNotIn(4, ctrl.datapaths)
            self.assertNotIn(4, ctrl.mac_to_port)
        finally:
            ctrl.close()
            if prev_port is None:
                os.environ.pop("PROMETHEUS_PORT", None)
            else:
                os.environ["PROMETHEUS_PORT"] = prev_port

    def test_slicing_service_and_dashboard_controllers(self) -> None:
        from controllers.dashboard_controller import DashboardController
        from controllers.service_controller import RyuController
        from controllers.slicing_controller import RyuSlicing
        from ryu.lib.packet.ethernet import ethernet as MockEthernet

        # 1. Topology slicing setup + ARP drop check
        slicing = RyuSlicing()
        dp1 = _MockDatapath(1)
        slicing.switch_features_handler(types.SimpleNamespace(msg=types.SimpleNamespace(datapath=dp1)))
        self.assertGreaterEqual(len(dp1.sent), 10)  # table-miss + 4 IP + 4 ARP + 1 IPv4 drop

        arp_pkt = MockEthernet(src=DEFAULT_HOSTS["h1"]["mac"], dst="ff:ff:ff:ff:ff:ff", ethertype=0x0806)
        before_arp = len(dp1.sent)
        slicing._packet_in_handler(
            types.SimpleNamespace(
                msg=types.SimpleNamespace(
                    datapath=dp1,
                    match={"in_port": 1},
                    data=arp_pkt,
                    buffer_id=DEFAULT_OFP_NO_BUFFER,
                )
            )
        )
        self.assertEqual(len(dp1.sent), before_arp)  # Unknown ARP safely dropped

        # 2. Service slicing setup + reactive Flood confinement
        service = RyuController()
        dp1_srv = _MockDatapath(1)
        service.switch_features_handler(types.SimpleNamespace(msg=types.SimpleNamespace(datapath=dp1_srv)))
        self.assertTrue(any(k == "udp_dst" for _, kw in dp1_srv.sent for k in kw.get("match", {})))

        ip_pkt = MockEthernet(src=DEFAULT_HOSTS["h1"]["mac"], dst=DEFAULT_HOSTS["h3"]["mac"], ethertype=0x0800)
        dp1_srv.sent.clear()
        service._packet_in_handler(
            types.SimpleNamespace(
                msg=types.SimpleNamespace(
                    datapath=dp1_srv,
                    match={"in_port": 1},
                    data=ip_pkt,
                    buffer_id=DEFAULT_OFP_NO_BUFFER,
                )
            )
        )
        # Controlled flood outputs to host 2 and S3 (port 4), NOT S2 (port 3)
        self.assertEqual(len(dp1_srv.sent), 1)
        msg_type, po_kwargs = dp1_srv.sent[0]
        self.assertEqual(msg_type, "PACKET_OUT")
        self.assertEqual([act[1] for act in po_kwargs["actions"]], [2, 4])

        # 3. Dashboard controller telemetry update
        prev_port = os.environ.get("PROMETHEUS_PORT")
        os.environ["PROMETHEUS_PORT"] = "0"
        dash = DashboardController()
        try:
            dash.metrics_server.ready.wait(timeout=3)
            dp1_dash = _MockDatapath(1)
            port_stat = types.SimpleNamespace(
                port_no=3,
                rx_packets=100,
                tx_packets=250,
                rx_bytes=12000,
                tx_bytes=362500,
                rx_errors=0,
                tx_errors=0,
            )
            dash._port_stats_reply_handler(
                types.SimpleNamespace(msg=types.SimpleNamespace(datapath=dp1_dash, body=[port_stat]))
            )
            snap = dash.metrics_store.snapshot()
            self.assertEqual(snap[1][3]["tx_bytes"], 362500)
        finally:
            dash.close()
            if prev_port is None:
                os.environ.pop("PROMETHEUS_PORT", None)
            else:
                os.environ["PROMETHEUS_PORT"] = prev_port


if __name__ == "__main__":
    unittest.main()
