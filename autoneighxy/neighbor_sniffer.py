# -*- coding: utf-8 -*-
"""Sniff neighbor control communications over the network"""

from scapy.all import Ether, ARP, IPv6, L2Socket, \
    ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RS, ICMPv6ND_RA, \
    ICMPv6NDOptDstLLAddr, ICMPv6NDOptSrcLLAddr, MTU, \
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


def send_icmp6(icmp6_pkt, iface):
    """Send an ICMPv6 packet to a specific interface

    This does not take into account routing table, so that allows sending
    packets to multicast address on the specified interface
    """
    s = L2Socket(iface=iface)
    # Add IPv6 header if it didn't exist
    if IPv6 not in icmp6_pkt:
        icmp6_pkt = IPv6() / icmp6_pkt
    try:
        s.send(Ether() / icmp6_pkt)
    finally:
        s.close()


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
            if LOG_NETWORK_PACKETS:
                logger.debug("[{0}] ARP who has {1} ?"
                             .format(iface, arppkt.pdst))
        elif arppkt.op == ARP.is_at:
            if LOG_NETWORK_PACKETS:
                logger.debug("[{0}] ARP {1} is at {2}"
                             .format(iface, arppkt.psrc, arppkt.hwsrc))
            self.update_neigh(iface, arppkt.pdst, arppkt.hwdst)

    def process_icmpv6_packet(self, iface, pkt):
        """Process a received ICMPv6 packet

        It forward Neighbor Discovery Protocol packets manually
        """
        ethpkt = pkt[Ether]
        ippkt = ethpkt[IPv6]
        # Forwarded packet
        fwdpkt = None

        if ICMPv6ND_NS in ippkt:
            # Neighbor Solicitation
            nspkt = ippkt[ICMPv6ND_NS]
            if LOG_NETWORK_PACKETS:
                logger.debug("[{0}] NSolicit for {1}"
                             .format(iface, nspkt.tgt))
            # There is a host behind iface which is using ip.src/eth.src
            self.update_neigh(iface, ippkt.src, ethpkt.src)
            # Reset checksum
            nspkt.cksum = None
            fwdpkt = nspkt
        elif ICMPv6ND_NA in ippkt:
            # Neighbor Advertisement, NOT to be forwarded.
            # The kernel answers to NS when configured with NDP proxy
            napkt = ippkt[ICMPv6ND_NA]
            if ICMPv6NDOptDstLLAddr in napkt:
                dst_lladdr = napkt[ICMPv6NDOptDstLLAddr].lladdr
                if LOG_NETWORK_PACKETS:
                    logger.debug("[{0}] NAdvert {1} is at {2}"
                                 .format(iface, napkt.tgt, dst_lladdr))
                self.update_neigh(iface, ippkt.src, ethpkt.src)
                self.update_neigh(iface, napkt.tgt, dst_lladdr)
        elif ICMPv6ND_RS in ippkt:
            # Router Solicitation
            if LOG_NETWORK_PACKETS:
                logger.debug("[{0}] RSolicit from {1}"
                             .format(iface, ippkt.src))
            self.update_neigh(iface, ippkt.src, ethpkt.src)
            rspkt = ippkt[ICMPv6ND_RS]
            rspkt.cksum = None
            fwdpkt = rspkt
        elif ICMPv6ND_RA in ippkt:
            # Router Advertisement
            if LOG_NETWORK_PACKETS:
                logger.debug("[{0}] RAdvert from {1}"
                             .format(iface, ippkt.src))
            self.update_neigh(iface, ippkt.src, ethpkt.src)
            # Set Proxy bit
            rapkt = ippkt[ICMPv6ND_RA]
            rapkt.P = 1
            rapkt.cksum = None
            #ippkt.src = None
            fwdpkt = rapkt

        # Forward IP packet if needed
        if fwdpkt is not None and not self.neigh.is_local_hw(ethpkt.src):
            for if_entry in self.neigh.values():
                if if_entry.iface != iface:
                    logger.debug("... Forward from {0} to {1}"
                                 .format(iface, if_entry.iface))
                    # Change hardware source address in RA
                    if ICMPv6NDOptSrcLLAddr in fwdpkt:
                        fwdpkt[ICMPv6NDOptSrcLLAddr].lladdr = if_entry.ifhwaddr

                    # Change IPv6 source address
                    if IPv6 in fwdpkt:
                        fwdpkt[IPv6].src = if_entry.llip6addr
                    else:
                        fwdpkt = IPv6(src=if_entry.llip6addr) / fwdpkt
                    send_icmp6(fwdpkt, if_entry.iface)

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
                            self.process_arp_packet(iface, pkt)
                        elif IPv6 in pkt:
                            self.process_icmpv6_packet(iface, pkt)

        finally:
            for iface, s in sockets.items():
                s.close()
