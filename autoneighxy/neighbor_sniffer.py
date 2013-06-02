# -*- coding: utf-8 -*-
"""Sniff neighbor control communications over the network"""

from scapy.all import Ether, ARP, IPv6, \
    ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, MTU, \
    conf, get_if_list
import logging
import select

from .neigh_table import NeighTable

logger = logging.getLogger(__name__)


# Log received packets, for debugging purpose
LOG_NETWORK_PACKETS = True


def get_nonloop_ifaces():
    """Get all network interface not being loopback"""
    return [i for i in get_if_list() if i != 'lo']


class NeighborSniffer(object):

    sniff_filter = 'arp or (ip6 and icmp6)'

    def __init__(self, ifaces=None):
        self.ifaces = ifaces if ifaces is not None else get_nonloop_ifaces()
        self.sync_ifaces()

    def sync_ifaces(self):
        """Get all non-loopback interfaces in internal data structures"""
        self.neigh = NeighTable(*self.ifaces)
        logger.info("Sniffing interfaces {0}".format(', '.join(self.ifaces)))
        logger.info("Current neighbor table:")
        for line in self.neigh.dump():
            logger.info("    " + line)

    def update_neigh(self, iface, ip, hw):
        """Update a neighbor entry"""
        return self.neigh.update(iface, ip, hw, update_proxy=True)

    def process_arp_packet(self, iface, pkt):
        """Process a received ARP packet

        Usual ARP messages are in one of these format:
            ARP who has {pdst}, tells {psrc}/{hwsrc}
            ARP is at {hwsrc} says {psrc}, to {pdst}/{hwdst}
        """
        arppkt = pkt[ARP]

        # There is a host behind iface which is using psrc/hwsrc
        self.update_neigh(iface, arppkt.psrc, arppkt.hwsrc)

        # Process dynamic updates with ARP is-at
        if arppkt.op == ARP.who_has:
            pass
        elif arppkt.op == ARP.is_at:
            self.update_neigh(iface, arppkt.pdst, arppkt.hwdst)

    def process_icmpv6_packet(self, iface, pkt):
        """Process a received ICMPv6 packet"""
        ethpkt = pkt[Ether]
        ippkt = pkt[IPv6]

        # There is a host behind iface which is using ip.src/eth.src
        self.update_neigh(iface, ippkt.src, ethpkt.src)

        if ICMPv6ND_NS in pkt:
            # Neighbor Sollicitation
            pass
        elif ICMPv6ND_NA in pkt:
            # Neighbor Advertisement
            napkt = pkt[ICMPv6ND_NA]
            if ICMPv6NDOptDstLLAddr in napkt:
                dst_lladdr = napkt[ICMPv6NDOptDstLLAddr].lladdr
                self.update_neigh(iface, napkt.tgt, dst_lladdr)

    def run(self):
        """Sniff neighbor control messages (ARP and NDP)"""
        sockets = {}
        try:
            for iface in self.ifaces:
                sockets[iface] = conf.L2listen(
                    iface=iface,
                    filter=self.sniff_filter)

            while True:
                sel = select.select(sockets.values(), [], [])
                for iface, s in sockets.items():
                    if s in sel[0]:
                        pkt = s.recv(MTU)
                        if pkt is None or Ether not in pkt:
                            continue
                        elif ARP in pkt:
                            if LOG_NETWORK_PACKETS:
                                logger.debug(
                                    "Got ARP from {0}: {1}"
                                    .format(iface, pkt.summary()))
                            self.process_arp_packet(iface, pkt)
                        elif IPv6 in pkt:
                            if LOG_NETWORK_PACKETS:
                                logger.debug(
                                    "Got IPv6 from {0}: {1}"
                                    .format(iface, pkt.summary()))
                            self.process_icmpv6_packet(iface, pkt)

        finally:
            for iface, s in sockets.items():
                s.close()
