/*! \file logging.h */

#pragma once

#define LOGGING_STR	"Configure logging\n"
#define FILTER_STR	"Filter log messages\n"

struct log_info;
void logging_vty_add_cmds();
void logging_vty_add_deprecated_subsys(void *ctx, const char *name);
struct vty;
struct log_target *osmo_log_vty2tgt(struct vty *vty);
