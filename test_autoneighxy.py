#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Test autoneighxy program"""

import autoneighxy
import logging


class ColoredFormatter(logging.Formatter):
    """Color logs in terminal"""
    COLORS = {
        'WARNING': '\033[33m',
        'INFO': '',
        'DEBUG': '\033[37m',
        'CRITICAL': '\033[1;31m',
        'ERROR': '\033[1;31m'
    }
    COLORS_RESET = '\033[0m'

    def __init__(self, msg):
        super(ColoredFormatter, self).__init__(msg)

    def format(self, record):
        line = super(ColoredFormatter, self).format(record)
        levelname = record.levelname
        if levelname in self.COLORS:
            line = self.COLORS[levelname] + line + self.COLORS_RESET
        return line


if __name__ == '__main__':
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    log_handler = logging.StreamHandler()
    log_handler.setFormatter(ColoredFormatter(
        '[%(levelname)5s] %(name)s: %(message)s'))
    logger.addHandler(log_handler)
    # TODO: parse sys.argv parameters to only bridge some interfaces
    try:
        autoneighxy.NeighborSniffer().run()
    except KeyboardInterrupt:
        pass
