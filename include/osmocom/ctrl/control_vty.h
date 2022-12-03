/*! \file control_vty.h */

#pragma once

#include <stdint.h>

/* Add the 'ctrl' section to VTY, containing the 'bind' command. */
int ctrl_vty_init(void *ctx);

/* Obtain the IP address configured by the 'ctrl'/'bind A.B.C.D' VTY command.
 * This should be fed to ctrl_interface_setup() once the configuration has been
 * read. */
const char *ctrl_vty_get_bind_addr(void);

/* Returns configured port passed to the 'line ctrl'/'bind' command or default_port. */
uint16_t ctrl_vty_get_bind_port(uint16_t default_port);
