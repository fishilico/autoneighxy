# -*- coding: utf-8 -*-
"""API to ip command-line tool"""

import logging
import re
import subprocess

logger = logging.getLogger(__name__)


class ApiIpError(Exception):
    """Error message from ip command"""

    def __init__(self, message, code=None):
        self.code = code
        self.message = message
        if code is not None:
            message += " (error {0})".format(code)
        super(ApiIpError, self).__init__(message)


def _run_show_command(cmdline):
    """Run a command which outputs something and yield its lines"""
    logger.debug("Run {0}".format(' '.join(cmdline)))
    p = subprocess.Popen(cmdline,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for line in p.stdout:
        yield line.decode('ascii', errors='ignore').strip()
    retval = p.wait()
    if retval:
        err = p.communicate()[1].decode('ascii', errors='ignore').strip()
        raise ApiIpError(err, code=retval)


def _run_do_command(cmdline):
    """Run a command without output but which might fail"""
    logger.debug("Run {0}".format(' '.join(cmdline)))
    p = subprocess.Popen(cmdline, stderr=subprocess.PIPE)
    retval = p.wait()
    if retval:
        err = p.communicate()[1].decode('ascii', errors='ignore').strip()
        raise ApiIpError(err, code=retval)


def list_neigh(iface=None):
    """List neighbours of a given interface

    Return a list of (iface, IPaddr, HWaddr) tuples
    """
    cmdline = ['dev', iface] if iface else []
    neigh = []
    for line in _run_show_command(['ip', 'neigh', 'show'] + cmdline):
        matches = re.match(
            r'^(?P<ip>\S+)( dev (?P<if>\S+))?.* lladdr (?P<hw>\S+)', line)
        if matches is not None:
            iff, ipaddr, hwaddr = matches.group('if', 'ip', 'hw')
            neigh.append((iff or iface, ipaddr, hwaddr))
        elif 'FAILED' not in line:
            raise ApiIpError("Unexpected line: " + line)
    return neigh


def del_neigh(iface, ip):
    """Remove a neighbor"""
    _run_do_command(['ip', 'neigh', 'del', ip, 'dev', iface])


def list_neigh_proxy(iface=None):
    """List neighbour proxies of a given interface

    Return a list of (iface, IPaddr) tuples
    """
    cmdline = ['dev', iface] if iface else []
    neigh = []
    for line in _run_show_command(['ip', 'neigh', 'show', 'proxy'] + cmdline):
        matches = re.match(r'^(?P<ip>\S+)( dev (?P<if>\S+))?', line)
        if matches is not None:
            iff, ipaddr = matches.group('if', 'ip')
            neigh.append((iff or iface, ipaddr))
        else:
            raise ApiIpError("Unexpected line: " + line)
    return neigh


def add_neigh_proxy(iface, ip):
    """Add a neighbor proxy"""
    try:
        _run_do_command(['ip', 'neigh', 'add', 'proxy', ip, 'dev', iface])
    except ApiIpError as e:
        # Ignore already-existing neughbors
        if e.code == 2 and 'File exists' in e.message:
            return
        raise e


def del_neigh_proxy(iface, ip):
    """Delete a neighbor proxy"""
    _run_do_command(['ip', 'neigh', 'del', 'proxy', ip, 'dev', iface])


def list_host_routes(iface=None):
    """List routes to specific hosts in local network

    Return a list of (iface, IPaddr) tuples
    """
    cmdline = ['dev', iface] if iface else []
    routes = []
    for line in _run_show_command(['ip', '-4', 'route', 'show'] + cmdline):
        matches = re.match(r'^(?P<ip>[0-9.]+) (dev (?P<if>\S+))?', line)
        if matches is not None:
            iff, ipaddr = matches.group('if', 'ip')
            routes.append((iff or iface, ipaddr))
    for line in _run_show_command(['ip', '-6', 'route', 'show'] + cmdline):
        line = line.lower()
        matches = re.match(r'^(?P<ip>[0-9a-f:]+) (dev (?P<if>\S+))?', line)
        if matches is not None:
            iff, ipaddr = matches.group('if', 'ip')
            routes.append((iff or iface, ipaddr))
    return routes


def add_route(iface, ip, prefixlen=None, via=None):
    """Add a route"""
    if prefixlen is None:
        prefixlen = 128 if ':' in ip else 32
    cmdline = ['ip', 'route', 'add', ip + '/' + str(prefixlen), 'dev', iface]
    if via:
        cmdline += ['via', via]
    try:
        _run_do_command(cmdline)
    except ApiIpError as e:
        # Ignore already-existing routes
        if e.code == 2 and 'File exists' in e.message:
            return
        raise e


def del_route(iface, ip, prefixlen=None, via=None):
    """Delete a route"""
    if prefixlen is None:
        prefixlen = 128 if ':' in ip else 32
    cmdline = ['ip', 'route', 'del', ip + '/' + str(prefixlen), 'dev', iface]
    if via:
        cmdline += ['via', via]
    _run_do_command(cmdline)
