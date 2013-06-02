# -*- coding: utf-8 -*-
"""Neighbor table management"""

import itertools
import logging
from scapy.all import get_if_hwaddr, in6_getifaddr, IPV6_ADDR_LINKLOCAL

from . import api_ip

logger = logging.getLogger(__name__)


class NeighTableIface(dict):
    """Store information about an interface entry of the neighbour table
    """

    def __init__(self, iface):
        """Retrieve current neighbors of interface iface in this object"""
        super(NeighTableIface, self).__init__()
        self.iface = iface
        # Hardware address
        self.ifhwaddr = None
        # Link-local IPv6 address
        self.llip6addr = None
        self.reload()

    def reload(self):
        """Reload tables from current state"""
        self.ifhwaddr = get_if_hwaddr(self.iface)
        lladdresses = [
            addr for addr, scope, iface in in6_getifaddr()
            if scope == IPV6_ADDR_LINKLOCAL and iface == self.iface]
        if len(lladdresses) != 1:
            raise Exception("Unable to find link-local address of {0}"
                            .format(self.iface))
        self.llip6addr = lladdresses[0]
        self.clear()
        for _, ip, hw in api_ip.list_neigh(iface=self.iface):
            self[ip] = hw
        self.proxies = set()
        for _, ip in api_ip.list_neigh_proxy(iface=self.iface):
            self.proxies.add(ip)
        self.host_routes = set()
        for _, ip in api_ip.list_host_routes(iface=self.iface):
            self.host_routes.add(ip)

    def dump(self):
        """Dump content for debugging purpose"""
        for ip, hw in self.items():
            yield '{0} @ {1}_{2}'.format(ip, self.iface, hw)
        for ip in self.proxies:
            yield '{0} @ {1}_PROXY'.format(ip, self.iface)
        for ip in self.host_routes:
            yield 'Route:{0} @ {1}'.format(ip, self.iface)

    def update(self, ip, hw):
        """Update a neighbor entry

        Return True if something changed
        """
        # Never list the self interface in neighbors, but the code may try do
        # add it because ifhwaddr is stored in this class and that makes
        # this test easy here.
        if hw == self.ifhwaddr:
            return False
        old_hw = self.get(ip)
        if old_hw is None:
            logger.info("New neighbor appeared: {0} @ {1}_{2}"
                        .format(ip, self.iface, hw))
        elif old_hw != hw:
            logger.info("HW address changed for {0} @ {1}: {2} -> {3}"
                        .format(ip, self.iface, old_hw, hw))
        else:
            return False

        # Here, we are sure ip-hw association needs to be updated
        self[ip] = hw
        if ip in self.proxies:
            self.del_neigh_proxy(ip)
        if ip not in self.host_routes:
            self.add_host_route(ip)
        return True

    def remove_neigh(self, ip):
        """Remove a neighbor.

        This flushes the kernel cache because that means an IP has moved to
        another location
        """
        try:
            api_ip.del_neigh(self.iface, ip)
        except api_ip.ApiIpError:
            pass
        self.del_host_route(ip)
        if ip in self:
            del self[ip]

    def add_neigh_proxy(self, ip):
        """Add a neighbor proxy"""
        if ip not in self.proxies:
            logger.info("Add Neighbor Proxy {0} @ {1}".format(ip, self.iface))
        try:
            api_ip.add_neigh_proxy(self.iface, ip)
        except api_ip.ApiIpError:
            # Failure is normal if the proxy already existed
            if ip in self.proxies:
                return
            # Reload tables
            self.reload()
            if ip in self.proxies:
                return
            # Let's try again, and failure goes up this time
            api_ip.add_neigh_proxy(self.iface, ip)
        self.proxies.add(ip)

    def del_neigh_proxy(self, ip):
        """Delete a neighbor proxy"""
        if ip in self.proxies:
            logger.info("Delete Neighbor Proxy {0} @ {1}"
                        .format(ip, self.iface))
        try:
            api_ip.del_neigh_proxy(self.iface, ip)
        except api_ip.ApiIpError:
            # Failure is normal if the proxy did not exist
            if ip not in self.proxies:
                return
            # Reload tables
            self.reload()
            if ip not in self.proxies:
                return
            # Let's try again, and failure goes up this time
            api_ip.del_neigh_proxy(self.iface, ip)
        self.proxies.discard(ip)

    def add_host_route(self, ip):
        """Add a route to an host"""
        if ip not in self.host_routes:
            logger.info("Add Host Route {0} @ {1}".format(ip, self.iface))
        try:
            api_ip.add_route(self.iface, ip)
        except api_ip.ApiIpError:
            # Failure is normal if the proxy already existed
            if ip in self.host_routes:
                return
            # Reload tables
            self.reload()
            if ip in self.host_routes:
                return
            # Let's try again, and failure goes up this time
            api_ip.add_route(self.iface, ip)
        self.host_routes.add(ip)

    def del_host_route(self, ip):
        """Delete a neighbor proxy"""
        if ip in self.host_routes:
            logger.info("Delete Host Route {0} @ {1}".format(ip, self.iface))
        try:
            api_ip.del_route(self.iface, ip)
        except api_ip.ApiIpError:
            # Failure is normal if the proxy did not exist
            if ip not in self.host_routes:
                return
            # Reload tables
            self.reload()
            if ip not in self.host_routes:
                return
            # Let's try again, and failure goes up this time
            api_ip.del_route(self.iface, ip)
        self.host_routes.discard(ip)


class NeighTable(dict):
    """Store information about a neighbor table.

    A neighbor table is a dict in following format:
        interface name (iface) -> IP address (ip) -> Hardware address (hw)
    """

    def __init__(self, *ifaces):
        """Initialise a neighbor table with some interfaces"""
        super(NeighTable, self).__init__()
        for iface in ifaces:
            self[iface] = NeighTableIface(iface)
        self.check_proxy()

    def add_iface(self, iface):
        """Add an interface and retrieve its current state"""
        self[iface] = NeighTableIface(iface)

    def dump(self):
        """Dump content for debugging purpose"""
        for entries in self.values():
            for line in entries.dump():
                yield line

    def is_local_hw(self, hw):
        """Test wether a hardware address is local to this host

        This only tests if hw is is one of the known interfaces.
        """
        return any([hw == entry.ifhwaddr for entry in self.values()])

    def update(self, iface, ip, hw, update_proxy=False):
        """Update a neighbour entry

        Return True if something changed
        """
        # Some packets have an empty source address, ignore them
        if ip in ['0.0.0.0', '::']:
            return False

        entry = self.get(iface)
        if entry is None:
            logger.error(
                "Error: add a neigh entry for unknown interface {0}"
                .format(iface))
            return False

        # Do nothing if I initiated the packet, it may be a proxy
        if hw == entry.ifhwaddr or self.is_local_hw(hw):
            return False

        # Remove the IP address if it was in an other interface
        for other_iface, other_entry in self.items():
            if iface != other_iface and ip in other_entry:
                logger.info("{0} has moved from {1} to {2}"
                            .format(ip, iface, other_iface))
                other_entry.remove_neigh(ip)

        if not entry.update(ip, hw):
            return False

        # Update the proxy if needed
        if update_proxy:
            self.check_proxy(updated_iface=iface, updated_ip=ip)
        return True

    def check_proxy(self, updated_iface=None, updated_ip=None):
        """Check the proxy state and add/remove entries if needed"""
        for entries in self.values():
            for ip in entries.keys():
                # Remove bad proxies
                if ip in entries.proxies:
                    entries.del_neigh_proxy(ip)
                # Add host routes
                if ip not in entries.host_routes:
                    entries.add_host_route(ip)
            # Remove no-longer existing host routes
            for ip in list(entries.host_routes):
                if ip not in entries:
                    entries.del_host_route(ip)
            # Remove proxy entries which no longer matches a neighbor
            for ip in list(entries.proxies):
                if all([ip not in e for e in self.values()]):
                    entries.del_neigh_proxy(ip)

        # Checks between interfaces
        ifaces = list(self.keys())
        for iface, p_iface in itertools.product(ifaces, ifaces):
            if p_iface == iface:
                continue
            # Each IP of iface needs to be proxyfied by p_iface
            entries = self[iface]
            p_entries = self[p_iface]
            for ip in list(entries.keys()):
                # Test wether ip has been seen by both iface and p_iface
                if ip in p_entries:
                    logger.warning(
                        "IP {0} seen from both {1} and {2}. Discarding both."
                        .format(ip, iface, p_iface))
                    entries.remove_neigh(ip)
                    p_entries.remove_neigh(ip)
                    continue

                # Add needed neigh proxy
                if ip not in p_entries.proxies:
                    p_entries.add_neigh_proxy(ip)
