# -*- coding: utf-8 -*-
"""API to sysctl configuration"""

import logging
import os

logger = logging.getLogger(__name__)


# Sysctl entries for each interface
SYSCTL_ENDPOINT = '/proc/sys'
SYSCTL_IP4_FORWARDING = 'net.ipv4.conf.{iface}.forwarding'
SYSCTL_IP4_PROXY_ARP = 'net.ipv4.conf.{iface}.proxy_arp'
SYSCTL_IP6_FORWARDING = 'net.ipv6.conf.{iface}.forwarding'
SYSCTL_IP6_PROXY_NDP = 'net.ipv6.conf.{iface}.proxy_ndp'


def ipv4_ifaces():
    """Return a set of IPv4 interfaces"""
    files = frozenset(os.listdir(SYSCTL_ENDPOINT + '/net/ipv4/conf'))
    return files - {'all', 'default'}


def ipv6_ifaces():
    """Return a set of IPv6 interfaces"""
    files = frozenset(os.listdir(SYSCTL_ENDPOINT + '/net/ipv6/conf'))
    return files - {'all', 'default'}


def ip_ifaces():
    """Return a set of IP interfaces"""
    return ipv4_ifaces() | ipv6_ifaces()


def read_sysctl(entry):
    """Read a sysctl entry and return its value, or None"""
    path = SYSCTL_ENDPOINT + '/' + '/'.join(entry.split('.'))
    if not os.path.exists(path):
        logger.debug("{} does not exist".format(entry))
        return
    try:
        with open(path, 'r') as f:
            return f.read()
    except IOError:
        logger.warning("unable to read {}".format(entry))
        return


def read_sysctl_int(entry):
    """Read an integer from a sysctl entry"""
    value = read_sysctl(entry)
    return int(value) if value else None


def write_sysctl(entry, value):
    """Write value to a sysctl entry. Return this value if successful"""
    path = SYSCTL_ENDPOINT + '/' + '/'.join(entry.split('.'))
    if not os.path.exists(path):
        logger.debug("{} does not exist".format(entry))
        return
    try:
        with open(path, 'w') as f:
            f.write(value)
            logger.debug("entry {} set to {}".format(entry, value))
            return value
    except IOError:
        logger.warning("unable to set {} to {}".format(entry, value))
        return


def write_sysctl_int(entry, value):
    """Write an integer into a sysctl entry"""
    value = write_sysctl(entry, str(value))
    return int(value) if value else None


def ckwrite_sysctl_int(entry, value):
    """Check wether entry is already equal to value and if not, set it"""
    val = read_sysctl_int(entry)
    if val is None or val == value:
        return val
    return write_sysctl_int(entry, value)


def activate_iface(iface):
    """Activate an interface for forwaring and neighbor proxying"""
    ckwrite_sysctl_int(SYSCTL_IP4_FORWARDING.format(iface=iface), 1)
    ckwrite_sysctl_int(SYSCTL_IP4_PROXY_ARP.format(iface=iface), 1)
    # Set IPv6 forwarding to 2 to still accept Router Advertisements
    ckwrite_sysctl_int(SYSCTL_IP6_FORWARDING.format(iface=iface), 2)
    ckwrite_sysctl_int(SYSCTL_IP6_PROXY_NDP.format(iface=iface), 1)

    # The 'all' interface also configure old IPv4 forwarding interface
    if iface == 'all':
        ckwrite_sysctl_int('net.ipv4.ip_forward', 1)


def deactivate_iface(iface):
    """Undo what activate_iface did"""
    ckwrite_sysctl_int(SYSCTL_IP4_FORWARDING.format(iface=iface), 0)
    ckwrite_sysctl_int(SYSCTL_IP4_PROXY_ARP.format(iface=iface), 0)
    ckwrite_sysctl_int(SYSCTL_IP6_FORWARDING.format(iface=iface), 0)
    ckwrite_sysctl_int(SYSCTL_IP6_PROXY_NDP.format(iface=iface), 0)
    if iface == 'all':
        ckwrite_sysctl_int('net.ipv4.ip_forward', 0)


def activate_only_ifaces(ifaces):
    """Activate only specified interfaces, and none other

    The 'all' configuration needs to be set to forward packets
    """
    if ifaces:
        activate_iface('all')
        for iface in ip_ifaces():
            if iface in ifaces:
                activate_iface(iface)
            else:
                deactivate_iface(iface)
    else:
        deactivate_iface('all')
        for iface in ip_ifaces():
            deactivate_iface(iface)


def iface_info(iface):
    """Get forwarding and neighbor proxying for an interface"""
    return {
        '4fwd': read_sysctl_int(SYSCTL_IP4_FORWARDING.format(iface=iface)),
        '4arpp': read_sysctl_int(SYSCTL_IP4_PROXY_ARP.format(iface=iface)),
        '6fwd': read_sysctl_int(SYSCTL_IP6_FORWARDING.format(iface=iface)),
        '6ndpp': read_sysctl_int(SYSCTL_IP6_PROXY_NDP.format(iface=iface)),
        }


def main():
    """Dump current state"""
    for iface in ['all', 'default'] + sorted(list(ip_ifaces())):
        info = iface_info(iface)
        print('{}:'.format(iface))
        print('    IPv4 forwarding: {}'.format(info['4fwd']))
        print('    IPv4 proxy ARP: {}'.format(info['4arpp']))
        print('    IPv6 forwarding: {}'.format(info['6fwd']))
        print('    IPv6 proxy NDP: {}'.format(info['6ndpp']))


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
