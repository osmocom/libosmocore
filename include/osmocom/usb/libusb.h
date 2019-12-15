#pragma once

#include <libusb.h>

int osmo_libusb_init(libusb_context **luctx);
void osmo_libusb_exit(libusb_context *luctx);
