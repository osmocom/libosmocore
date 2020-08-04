#!/usr/bin/env python
#
# License: MIT
# Copyright 2019 by Sysmocom s.f.m.c. GmbH
# Author: Alexander Couzens <lynxis@fe80.eu>

import logging
import socket

from gsmtap import GSMTAP_TYPE_OSMOCORE_LOG, gsmtap_hdr, gsmtap_log, TooSmall

LOG = logging.getLogger("gsmlogreader")

def parse_gsm(packet):
    hdr = None

    try:
        hdr = gsmtap_hdr(packet)
    except TooSmall:
        return None

    if hdr.type != GSMTAP_TYPE_OSMOCORE_LOG:
        return None

    if len(packet) <= hdr.hdr_len:
        return None

    try:
        return gsmtap_log(packet[hdr.hdr_len:])
    except TooSmall:
        return None

def gsmtaplevel_to_loglevel(level):
    """ convert a gsmtap log level into a python log level """
    if level <= 1:
        return logging.DEBUG
    if level <= 3:
        return logging.INFO
    if level <= 5:
        return logging.WARNING

    return logging.ERROR

def convert_gsmtap_log(gsmtap):
    level = gsmtaplevel_to_loglevel(gsmtap.level)

    attr = {
        "name": "gsmtap",
        "levelno": level,
        "levelname": gsmtap_get_logname(gsmtap.level),
        "pathname": gsmtap.filename,
        "lineno": gsmtap.fileline_nr,
        "processName": gsmtap.proc_name,
        "process": gsmtap.pid,
        "module": gsmtap.subsys,
        "created": float(gsmtap.sec + gsmtap.usec / 1000000.0),
        "msec": int(gsmtap.usec / 1000),
        "msg": gsmtap.message.replace('\n', ' '),
        }
    return attr

def gsmtap_get_logname(level):
    names = {
        1: "DEBUG",
        3: "INFO",
        5: "NOTICE",
        7: "ERROR",
        8: "FATAL",
        }
    if level in names:
        return names[level]
    return "UNKNOWN"

if __name__ == "__main__":
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('0.0.0.0', 4729)
    sock.bind(server_address)

    logger = logging.getLogger("gsmtap")
    logformat = "%(asctime)s %(message)s"
    logging.basicConfig(format=logformat, level=logging.DEBUG)


    while True:
        data, address = sock.recvfrom(4096)
        log = parse_gsm(data)
        if not log:
            continue

        record = logging.makeLogRecord(convert_gsmtap_log(log))
        logger.handle(record)
