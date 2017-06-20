/*! \file logging.h */

#pragma once

#define LOGGING_STR	"Configure log message to this terminal\n"
#define FILTER_STR	"Filter log messages\n"

struct log_info;
void logging_vty_add_cmds();
struct vty;
struct log_target *osmo_log_vty2tgt(struct vty *vty);
