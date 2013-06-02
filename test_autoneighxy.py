#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Test autoneighxy program"""

import autoneighxy
import logging


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


if __name__ == '__main__':
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    log_handler = logging.StreamHandler()
    log_handler.setFormatter(ColoredFormatter(
        '%(asctime)s [%(levelname)5s] %(name)s: %(message)s',
        datefmt='%H:%M:%S'))
    logger.addHandler(log_handler)
    # TODO: parse sys.argv parameters to only bridge some interfaces
    try:
        autoneighxy.NeighborSniffer().run()
    except KeyboardInterrupt:
        pass
