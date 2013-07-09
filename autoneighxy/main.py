# -*- coding: utf-8 -*-
"""Entry point of autoneighxy"""


import logging
import logging.handlers
import optparse
import os

from . import __version__, neighbor_sniffer, sysctl


class ColoredFormatter(logging.Formatter):
    """Color logs in terminal"""
    COLORS = {
        'DEBUG': '\033[37m',
        'INFO': '',
        'WARNING': '\033[1;33m',
        'ERROR': '\033[1;31m',
        'CRITICAL': '\033[1;31m',
    }
    COLORS_RESET = '\033[0m'

    def __init__(self, *args, **kwargs):
        super(ColoredFormatter, self).__init__(*args, **kwargs)

    def format(self, record):
        line = super(ColoredFormatter, self).format(record)
        levelname = record.levelname
        if levelname in self.COLORS:
            line = self.COLORS[levelname] + line + self.COLORS_RESET
        return line


def main(argv):
    """Parse command line and start to sniff the network"""

    parser = optparse.OptionParser(
        usage="usage: %prog [options] [iface1 [iface2 ...]]",
        version="%prog " + __version__)
    parser.add_option('-c', '--color', action='store_true', dest='color',
        help="use colors in logging (never enabled for syslog)", default=False)
    parser.add_option('-d', '--debug', action='store_true', dest='debug',
        help="log debug messages", default=False)
    parser.add_option('-n', '--nosysctl', action='store_true', dest='nosysctl',
        help="do not configure any sysctl", default=False)
    parser.add_option('-s', '--syslog', action='store_true', dest='syslog',
        help="log messages to syslog", default=False)

    opts, ifaces = parser.parse_args(argv)
    ifaces = ifaces[1:]

    # Test interfaces
    available_ifaces = neighbor_sniffer.get_nonloop_ifaces()
    bad_ifaces = set(ifaces) - set(available_ifaces)
    if bad_ifaces:
        parser.error("Unavailable interfaces: {}".format(', '.join(bad_ifaces)))
    if not ifaces:
        ifaces = available_ifaces

    # Setup logging
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if opts.debug else logging.INFO)
    logging_format = '[%(levelname)s] %(name)s: %(message)s'
    if opts.syslog:
        log_handler = logging.handlers.SysLogHandler(
            '/dev/log',
            facility=logging.handlers.SysLogHandler.LOG_DAEMON)
        log_handler.setFormatter(logging.Formatter(
            'autoneighxy[{}]: {}'.format(os.getpid()), logging_format))
        root_logger.addHandler(log_handler)
    else:
        log_handler = logging.StreamHandler()
        fmt_class = ColoredFormatter if opts.color else logging.Formatter
        log_handler.setFormatter(fmt_class('%(asctime)s ' + logging_format, datefmt='%H:%M:%S'))
        root_logger.addHandler(log_handler)

    # Configure sysctl
    if not opts.nosysctl:
        sysctl.activate_only_ifaces(ifaces)

    # Run sniffer until keyboard interrupt
    sniffer = neighbor_sniffer.NeighborSniffer(ifaces or None)
    try:
        sniffer.run()
    except KeyboardInterrupt:
        pass
