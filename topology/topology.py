"""Mininet diamond network topology with dual 10 Mbps / 1 Mbps bandwidth slices."""

from __future__ import annotations

import os

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController


def build_and_run_topology() -> None:
    """Create and launch the 4-switch, 4-host dual-slice Mininet testbed."""
    controller_ip = os.getenv("RYU_CONTROLLER_IP", "127.0.0.1")
    controller_port = int(os.getenv("RYU_CONTROLLER_PORT", "6633"))

    net = Mininet(
        controller=RemoteController,
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=False,
    )

    info("\n--- Adding remote SDN controller ---\n")
    c0 = net.addController(
        "c0",
        controller=RemoteController,
        ip=controller_ip,
        port=controller_port,
    )
    c0.start()

    info("\n--- Adding OpenFlow 1.3 switches (DPID 1-4) ---\n")
    s1 = net.addSwitch("s1", dpid="1", protocols="OpenFlow13")
    s2 = net.addSwitch("s2", dpid="2", protocols="OpenFlow13")
    s3 = net.addSwitch("s3", dpid="3", protocols="OpenFlow13")
    s4 = net.addSwitch("s4", dpid="4", protocols="OpenFlow13")

    info("\n--- Adding hosts (h1-h4) ---\n")
    h1 = net.addHost("h1", mac="00:00:00:00:00:01", ip="10.0.0.1/24")
    h2 = net.addHost("h2", mac="00:00:00:00:00:02", ip="10.0.0.2/24")
    h3 = net.addHost("h3", mac="00:00:00:00:00:03", ip="10.0.0.3/24")
    h4 = net.addHost("h4", mac="00:00:00:00:00:04", ip="10.0.0.4/24")

    info("\n--- Connecting host access links ---\n")
    net.addLink(h1, s1, port1=1, port2=1)
    net.addLink(h2, s1, port1=1, port2=2)
    net.addLink(s4, h3, port1=3, port2=1)
    net.addLink(s4, h4, port1=4, port2=1)

    info("\n--- Creating Upper Slice (S1 -- S2 -- S4 @ 10 Mbps) ---\n")
    net.addLink(s1, s2, port1=3, port2=1, bw=10)
    net.addLink(s2, s4, port1=2, port2=1, bw=10)

    info("\n--- Creating Lower Slice (S1 -- S3 -- S4 @ 1 Mbps) ---\n")
    net.addLink(s1, s3, port1=4, port2=1, bw=1)
    net.addLink(s3, s4, port1=2, port2=2, bw=1)

    info("\n--- Starting Mininet network ---\n")
    net.start()
    try:
        CLI(net)
    finally:
        info("\n--- Stopping Mininet network ---\n")
        net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    build_and_run_topology()
