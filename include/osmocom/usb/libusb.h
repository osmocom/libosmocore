#pragma once
/* libusb utilities
 *
 * (C) 2010-2019 by Harald Welte <hwelte@hmw-consulting.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <libusb.h>

#define USB_MAX_PATH_LEN 20

struct dev_id {
	uint16_t vendor_id;
	uint16_t product_id;
};

/* structure describing a single matching interface found */
struct usb_interface_match {
	/* libusb device E*/
	libusb_device *usb_dev;
	/* Vendor ID of the device running matching interface */
	uint16_t vendor;
	/* Product ID of the device running matching interface */
	uint16_t product;
	/* USB Bus Address */
	uint8_t addr;
	/* physical path */
	char path[USB_MAX_PATH_LEN];
	/* configuration of matching interface */
	uint8_t configuration;
	/* interface number of matching interface */
	uint8_t interface;
	/* altsetting of matching interface */
	uint8_t altsetting;
	/* bInterfaceClass of matching interface */
	uint8_t class;
	/* bInterfaceSubClass of matching interface */
	uint8_t sub_class;
	/* bInterfaceProtocol of matching interface */
	uint8_t protocol;
	/* index of string descriptor of matching interface */
	uint8_t string_idx;
};


char *osmo_libusb_dev_get_path_buf(char *buf, size_t bufsize, libusb_device *dev);
char *osmo_libusb_dev_get_path_c(void *ctx, libusb_device *dev);

libusb_device **osmo_libusb_find_matching_usb_devs(void *ctx, struct libusb_context *luctx,
						   const struct dev_id *dev_ids);

libusb_device *osmo_libusb_find_matching_dev_path(struct libusb_context *luctx,
						  const struct dev_id *dev_ids,
						  const char *path);

libusb_device *osmo_libusb_find_matching_dev_serial(struct libusb_context *luctx,
						    const struct dev_id *dev_ids,
						    const char *serial);

int osmo_libusb_dev_find_matching_interfaces(libusb_device *dev, int class, int sub_class,
					     int protocol, struct usb_interface_match *out,
					     unsigned int out_len);

int osmo_libusb_find_matching_interfaces(libusb_context *luctx, const struct dev_id *dev_ids,
					 int class, int sub_class, int protocol,
					 struct usb_interface_match *out, unsigned int out_len);

libusb_device_handle *osmo_libusb_open_claim_interface(void *ctx, libusb_context *luctx,
							const struct usb_interface_match *ifm);

int osmo_libusb_get_ep_addrs(libusb_device_handle *devh, unsigned int if_num,
			     uint8_t *out, uint8_t *in, uint8_t *irq);


int osmo_libusb_init(libusb_context **luctx);
void osmo_libusb_exit(libusb_context *luctx);
