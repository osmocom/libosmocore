#pragma once

#include <ares.h>

#include <osmocom/core/utils.h>

extern struct value_string ares_status_strs[25];
extern ares_channel osmo_ares_channel;

int osmo_ares_init();
