#!/usr/bin/env python
# License: MIT
# Copyright 2019 by Sysmocom s.f.m.c. GmbH
# Author: Alexander Couzens <lynxis@fe80.eu>

import struct

GSMTAP_VERSION = 0x02

GSMTAP_TYPE_OSMOCORE_LOG = 0x10

class TooSmall(RuntimeError):
    pass

# struct gsmtap_hdr {
#     uint8_t version;    /*!< version, set to 0x01 currently */
#     uint8_t hdr_len;    /*!< length in number of 32bit words */
#     uint8_t type;       /*!< see GSMTAP_TYPE_* */
#     uint8_t timeslot;   /*!< timeslot (0..7 on Um) */
#
#     uint16_t arfcn;     /*!< ARFCN (frequency) */
#     int8_t signal_dbm;  /*!< signal level in dBm */
#     int8_t snr_db;      /*!< signal/noise ratio in dB */
#
#     uint32_t frame_number;  /*!< GSM Frame Number (FN) */
#
#     uint8_t sub_type;   /*!< Type of burst/channel, see above */
#     uint8_t antenna_nr; /*!< Antenna Number */
#     uint8_t sub_slot;   /*!< sub-slot within timeslot */
#     uint8_t res;        /*!< reserved for future use (RFU) */
#
# }

class gsmtap_hdr():
    def __init__(self, data):
        if len(data) < 2:
            raise TooSmall()
        self.version, self.hdr_len = struct.unpack('!BB', data[0:2])
        self.hdr_len *= 4

        if self.hdr_len >= 3:
            self.type = struct.unpack('!B', data[2:3])[0]

# /*! Structure of the GSMTAP libosmocore logging header */
# struct gsmtap_osmocore_log_hdr {
# 	struct {
# 		uint32_t sec;
# 		uint32_t usec;
# 	} ts;
# 	char proc_name[16];	/*!< name of process */
# 	uint32_t pid;		/*!< process ID */
# 	uint8_t level;		/*!< logging level */
# 	uint8_t _pad[3];
# 	/* TODO: color */
# 	char subsys[16];	/*!< logging sub-system */
# 	struct {
# 		char name[32];	/*!< source file name */
# 		uint32_t line_nr;/*!< line number */
# 	} src_file;
# } __attribute__((packed));

class gsmtap_log():
    def __init__(self, data):
        packformat = '!II16sIBxxx16s32sI'
        packlen = struct.calcsize(packformat)
        if len(data) < packlen:
            raise TooSmall()
        self.sec, self.usec, \
                self.proc_name, self.pid, \
                self.level, self.subsys, \
                self.filename, self.fileline_nr = struct.unpack(packformat, data[:packlen])

        message_len = len(data) - packlen
        if message_len > 0:
            self.message = data[packlen:].decode('utf-8')
