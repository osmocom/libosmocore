/*! \file gprs_ns_frgre.h */

#pragma once

struct gprs_nsvc;
struct msgb;

int gprs_ns_frgre_sendmsg(struct gprs_nsvc *nsvc, struct msgb *msg);
