/* libosmocore integration with libusb-1.0
 *
 * (C) 2019-2019 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: GPL-2.0+
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
 */
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <poll.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>

#include <libusb.h>

#include <osmocom/usb/libusb.h>

/***********************************************************************
 * logging integration
 ***********************************************************************/

#define DLUSB	DLINP

#ifdef LIBUSB_LOG_CB_CONTEXT /* introduced in 1.0.23 */
static const int usb2logl[] = {
	[LIBUSB_LOG_LEVEL_NONE] = LOGL_FATAL,
	[LIBUSB_LOG_LEVEL_ERROR] = LOGL_ERROR,
	[LIBUSB_LOG_LEVEL_WARNING] = LOGL_NOTICE,
	[LIBUSB_LOG_LEVEL_INFO] = LOGL_INFO,
	[LIBUSB_LOG_LEVEL_DEBUG] = LOGL_DEBUG,
};

/* called by libusb if it wants to log something */
static void libosmo_usb_log_cb(libusb_context *luctx, enum libusb_log_level level_usb, const char *str)
{
	int level = LOGL_NOTICE;

	if (level_usb < ARRAY_SIZE(usb2logl))
		level = usb2logl[level_usb];

	LOGP(DLUSB, level, "%s", str);
}
#endif /* LIBUSB_LOG_CB_CONTEXT */

/***********************************************************************
 * select loop integration
 ***********************************************************************/

static int osmo_usb_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	libusb_context *luctx = ofd->data;

	/* we assume that we're running Linux v2.6.27 with timerfd support here
	 * and hence don't have to perform manual timeout handling.  See
	 * "Notes on time-based events" at
	 * http://libusb.sourceforge.net/api-1.0/group__libusb__poll.html */
	struct timeval zero_tv = { 0, 0 };
	libusb_handle_events_timeout(luctx, &zero_tv);

	return 0;
}

/* called by libusb if it wants to add a file-descriptor */
static void osmo_usb_added_cb(int fd, short events, void *user_data)
{
	struct osmo_fd *ofd = talloc_zero(OTC_GLOBAL, struct osmo_fd);
	libusb_context *luctx = user_data;
	unsigned int when = 0;
	int rc;

	if (events & POLLIN)
		when |= OSMO_FD_READ;
	if (events & POLLOUT)
		when |= OSMO_FD_WRITE;

	osmo_fd_setup(ofd, fd, when, osmo_usb_fd_cb, luctx, 0);
	rc = osmo_fd_register(ofd);
	if (rc)
		LOGP(DLUSB, LOGL_ERROR, "osmo_fd_register() failed with rc=%d\n", rc);
}

/* called by libusb if it wants to remove a file-descriptor */
static void osmo_usb_removed_cb(int fd, void *user_data)
{
	struct osmo_fd *ofd = osmo_fd_get_by_fd(fd);
	if (!ofd)
		return;
	osmo_fd_unregister(ofd);
	talloc_free(ofd);
}

/***********************************************************************
 * utility functions
 ***********************************************************************/

/*! obtain the string representation of the USB device path of given device.
 *  \param[out] buf Output string buffer
 *  \param[in] bufsize Size of output string buffer in bytes
 *  \param[in] dev USB device whose bus path we want to obtain
 *  \returns pointer to 'buf' in case of success; NULL in case of error */
char *osmo_libusb_dev_get_path_buf(char *buf, size_t bufsize, libusb_device *dev)
{
#if (defined(LIBUSB_API_VERSION) && LIBUSB_API_VERSION >= 0x01000102) || \
    (defined(LIBUSBX_API_VERSION) && LIBUSBX_API_VERSION >= 0x01000102)
	struct osmo_strbuf sb = { .buf = buf, .len = bufsize };
	uint8_t path[8];
	int r,j;
	r = libusb_get_port_numbers(dev, path, sizeof(path));
	if (r > 0) {
		OSMO_STRBUF_PRINTF(sb, "%d-%d", libusb_get_bus_number(dev), path[0]);
		for (j = 1; j < r; j++){
			OSMO_STRBUF_PRINTF(sb, ".%d", path[j]);
		}
	}
	return buf;
#else
# warning "libusb too old - building without USB path support!"
	return NULL;
#endif
}

/*! obtain the string representation of the USB device path of given device.
 *  \param[in] talloc context from which to dynamically allocate output string buffer
 *  \param[in] dev USB device whose bus path we want to obtain
 *  \returns pointer to 'buf' in case of success; NULL in case of error */
char *osmo_libusb_dev_get_path_c(void *ctx, libusb_device *dev)
{
	char *buf = talloc_zero_size(ctx, USB_MAX_PATH_LEN);
	if (!buf)
		return NULL;
	return osmo_libusb_dev_get_path_buf(buf, USB_MAX_PATH_LEN, dev);
}

static int match_dev_id(const struct libusb_device_descriptor *desc, const struct dev_id *id)
{
	if ((desc->idVendor == id->vendor_id) && (desc->idProduct == id->product_id))
		return 1;
	return 0;
}

static int match_dev_ids(const struct libusb_device_descriptor *desc, const struct dev_id *ids)
{
	const struct dev_id *id;

	for (id = ids; id->vendor_id || id->product_id; id++) {
		if (match_dev_id(desc, id))
			return 1;
	}
	return 0;
}

/*! Find USB devices matching the specified list of USB VendorID/ProductIDs
 *  \param[in] ctx talloc context from which to allocate output data
 *  \param[in] luctx libusb context on which to operate
 *  \param[in] dev_ids zero-terminated array of VendorId/ProductId tuples
 *  \returns array of up to 256 libusb_device pointers; NULL in case of error */
libusb_device **osmo_libusb_find_matching_usb_devs(void *ctx, struct libusb_context *luctx,
						   const struct dev_id *dev_ids)
{
	libusb_device **list;
	libusb_device **out = talloc_zero_array(ctx, libusb_device *, 256);
	libusb_device **cur = out;
	unsigned int i;
	int rc;

	if (!out)
		return NULL;

	rc = libusb_get_device_list(luctx, &list);
	if (rc <= 0) {
		perror("No USB devices found");
		talloc_free(out);
		return NULL;
	}

	for (i = 0; list[i] != NULL; i++) {
		struct libusb_device_descriptor dev_desc;
		libusb_device *dev = list[i];

		rc = libusb_get_device_descriptor(dev, &dev_desc);
		if (rc < 0) {
			perror("Couldn't get device descriptor\n");
			libusb_unref_device(dev);
			continue;
		}

		if (match_dev_ids(&dev_desc, dev_ids)) {
			*cur = dev;
			cur++;
			/* overflow check */
			if (cur >= out + 256)
				break;
		} else
			libusb_unref_device(dev);
	}
	if (cur == out) {
		libusb_free_device_list(list, 1);
		talloc_free(out);
		return NULL;
	}

	libusb_free_device_list(list, 0);
	return out;
}

/*! Find a USB device of matching VendorID/ProductID at given path.
 *  \param[in] luctx libusb context on which to operate
 *  \param[in] dev_ids zer-oterminated array of VendorId/ProductId tuples
 *  \param[in] path string representation of USB path
 *  \returns libusb_device if there was exactly one match; NULL otherwise */
libusb_device *osmo_libusb_find_matching_dev_path(struct libusb_context *luctx,
						  const struct dev_id *dev_ids,
						  const char *path)
{
	libusb_device **list;
	libusb_device *match = NULL;
	unsigned int i;
	int rc;

	rc = libusb_get_device_list(luctx, &list);
	if (rc <= 0)
		return NULL;

	for (i = 0; list[i] != NULL; i++) {
		struct libusb_device_descriptor dev_desc;
		libusb_device *dev = list[i];
		char pathbuf[128];

		rc = libusb_get_device_descriptor(dev, &dev_desc);
		if (rc < 0) {
			LOGP(DLUSB, LOGL_ERROR, "couldn't get device descriptor\n");
			continue;
		}

		/* check if device doesn't match */
		if (!match_dev_ids(&dev_desc, dev_ids))
			continue;

		/* check if path doesn't match */
		if (path) {
			osmo_libusb_dev_get_path_buf(pathbuf, sizeof(pathbuf), dev);
			if (strcmp(pathbuf, path))
				continue;
		}

		if (match) {
			/* we already have a match, but now found a second -> FAIL */
			libusb_free_device_list(list, 1);
			LOGP(DLUSB, LOGL_ERROR, "Found more than one matching USB device\n");
			return NULL;
		} else
			match = dev;
	}

	if (!match) {
		/* no match: free the list with automatic unref of all devices */
		libusb_free_device_list(list, 1);
		return NULL;
	}

	/* unref all devices *except* the match we found */
	for (i = 0; list[i] != NULL; i++) {
		libusb_device *dev = list[i];
		if (dev != match)
			libusb_unref_device(dev);
	}
	/* free the list *without* automatic unref of all devices */
	libusb_free_device_list(list, 0);
	return match;
}

/*! Find a USB device of matching VendorID/ProductID and given iSerial string.
 *  \param[in] luctx libusb context on which to operate
 *  \param[in] dev_ids zer-oterminated array of VendorId/ProductId tuples
 *  \param[in] serial string representation of serial number
 *  \returns libusb_device if there was exactly one match; NULL otherwise */
libusb_device *osmo_libusb_find_matching_dev_serial(struct libusb_context *luctx,
						    const struct dev_id *dev_ids,
						    const char *serial)
{
	libusb_device **list;
	libusb_device *match = NULL;
	unsigned int i;
	int rc;

	rc = libusb_get_device_list(luctx, &list);
	if (rc <= 0)
		return NULL;

	for (i = 0; list[i] != NULL; i++) {
		struct libusb_device_descriptor dev_desc;
		libusb_device *dev = list[i];

		rc = libusb_get_device_descriptor(dev, &dev_desc);
		if (rc < 0) {
			LOGP(DLUSB, LOGL_ERROR, "couldn't get device descriptor\n");
			continue;
		}

		/* check if device doesn't match */
		if (!match_dev_ids(&dev_desc, dev_ids))
			continue;

		/* check if serial number string doesn't match */
		if (serial) {
			char strbuf[256];
			libusb_device_handle *devh;
			rc = libusb_open(dev, &devh);
			if (rc < 0) {
				LOGP(DLUSB, LOGL_ERROR, "Cannot open USB Device: %s\n",
					libusb_strerror(rc));
				/* there's no point in continuing here, as we don't know if there
				 * are multiple matches if we cannot read the iSerial string of all
				 * devices with matching vid/pid */
				libusb_free_device_list(list, 1);
				return NULL;
			}
			rc = libusb_get_string_descriptor_ascii(devh, dev_desc.iSerialNumber,
								(uint8_t *) strbuf, sizeof(strbuf));
			if (rc < 0) {
				LOGP(DLUSB, LOGL_ERROR, "Cannot read USB Descriptor: %s\n",
					libusb_strerror(rc));
				libusb_close(devh);
				continue;
			}
			libusb_close(devh);
			if (strcmp(strbuf, serial))
				continue;
		}

		if (match) {
			/* we already have a match, but now found a second -> FAIL */
			libusb_free_device_list(list, 1);
			LOGP(DLUSB, LOGL_ERROR, "Found more than one matching USB device\n");
			return NULL;
		} else
			match = dev;
	}

	if (!match) {
		/* no match: free the list with automatic unref of all devices */
		libusb_free_device_list(list, 1);
		return NULL;
	}

	/* unref all devices *except* the match we found */
	for (i = 0; list[i] != NULL; i++) {
		libusb_device *dev = list[i];
		if (dev != match)
			libusb_unref_device(dev);
	}
	/* free the list *without* automatic unref of all devices */
	libusb_free_device_list(list, 0);
	return match;
}


/*! find a matching interface among all interfaces of the given USB device.
 *  \param[in] dev USB device in which we shall search
 *  \param[in] class USB Interface Class to look for
 *  \param[in] sub_class USB Interface Subclass to look for
 *  \param[in] protocol USB Interface Protocol to look for
 *  \param[out] out User-allocated array for storing matches
 *  \param[in] out_len Length of out array
 *  \returns number of matching interfaces; negative in case of error */
int osmo_libusb_dev_find_matching_interfaces(libusb_device *dev, int class, int sub_class,
					     int protocol, struct usb_interface_match *out,
					     unsigned int out_len)
{
	struct libusb_device_descriptor dev_desc;
	int rc, i, out_idx = 0;
	uint8_t addr;
	char pathbuf[USB_MAX_PATH_LEN];
	char *path;

	rc = libusb_get_device_descriptor(dev, &dev_desc);
	if (rc < 0) {
		perror("Couldn't get device descriptor\n");
		return -EIO;
	}

	addr = libusb_get_device_address(dev);
	path = osmo_libusb_dev_get_path_buf(pathbuf, sizeof(pathbuf), dev);

	/* iterate over all configurations */
	for (i = 0; i < dev_desc.bNumConfigurations; i++) {
		struct libusb_config_descriptor *conf_desc;
		int j;

		rc = libusb_get_config_descriptor(dev, i, &conf_desc);
		if (rc < 0) {
			fprintf(stderr, "Couldn't get config descriptor %u\n", i);
			continue;
		}
		/* iterate over all interfaces */
		for (j = 0; j < conf_desc->bNumInterfaces; j++) {
			const struct libusb_interface *intf = &conf_desc->interface[j];
			int k;
			/* iterate over all alternate settings */
			for (k = 0; k < intf->num_altsetting; k++) {
				const struct libusb_interface_descriptor *if_desc;
				if_desc = &intf->altsetting[k];
				if (class >= 0 && if_desc->bInterfaceClass != class)
					continue;
				if (sub_class >= 0 && if_desc->bInterfaceSubClass != sub_class)
					continue;
				if (protocol >= 0 && if_desc->bInterfaceProtocol != protocol)
					continue;
				/* MATCH! */
				out[out_idx].usb_dev = dev;
				out[out_idx].vendor = dev_desc.idVendor;
				out[out_idx].product = dev_desc.idProduct;
				out[out_idx].addr = addr;
				OSMO_STRLCPY_ARRAY(out[out_idx].path, path);
				out[out_idx].path[sizeof(out[out_idx].path)-1] = '\0';
				out[out_idx].configuration = conf_desc->bConfigurationValue;
				out[out_idx].interface = if_desc->bInterfaceNumber;
				out[out_idx].altsetting = if_desc->bAlternateSetting;
				out[out_idx].class = if_desc->bInterfaceClass;
				out[out_idx].sub_class = if_desc->bInterfaceSubClass;
				out[out_idx].protocol = if_desc->bInterfaceProtocol;
				out[out_idx].string_idx = if_desc->iInterface;
				out_idx++;
				if (out_idx >= out_len)
					return out_idx;
			}
		}
	}
	return out_idx;
}

/*! find matching interfaces among a list devices of specified VendorId/ProductID tuples.
 *  \param[in] luctx libusb context on which to operate
 *  \param[in] dev_ids zero-terminated array of VendorId/ProductId tuples
 *  \param[in] class USB Interface Class to look for
 *  \param[in] sub_class USB Interface Subclass to look for
 *  \param[in] protocol USB Interface Protocol to look for
 *  \param[out] out User-allocated array for storing matches
 *  \param[in] out_len Length of out array
 *  \returns number of matching interfaces; negative in case of error */
int osmo_libusb_find_matching_interfaces(libusb_context *luctx, const struct dev_id *dev_ids,
					 int class, int sub_class, int protocol,
					 struct usb_interface_match *out, unsigned int out_len)
{
	struct usb_interface_match *out_cur = out;
	unsigned int out_len_remain = out_len;
	libusb_device **list;
	libusb_device **dev;

	list = osmo_libusb_find_matching_usb_devs(NULL, luctx, dev_ids);
	if (!list)
		return 0;

	for (dev = list; *dev; dev++) {
		int rc;

#if 0
		struct libusb_device_descriptor dev_desc;
		uint8_t ports[8];
		uint8_t addr;
		rc = libusb_get_device_descriptor(*dev, &dev_desc);
		if (rc < 0) {
			perror("Cannot get device descriptor");
			continue;
		}

		addr = libusb_get_device_address(*dev);

		rc = libusb_get_port_numbers(*dev, ports, sizeof(ports));
		if (rc < 0) {
			perror("Cannot get device path");
			continue;
		}

		printf("Found USB Device %04x:%04x at address %d\n",
			dev_desc.idVendor, dev_desc.idProduct, addr);
#endif

		rc = osmo_libusb_dev_find_matching_interfaces(*dev, class, sub_class,
							      protocol, out_cur, out_len_remain);
		if (rc < 0)
			continue;
		out_cur += rc;
		out_len_remain -= rc;

	}

	/* unref / free list */
	for (dev = list; *dev; dev++)
		libusb_unref_device(*dev);
	talloc_free(list);

	return out_len - out_len_remain;
}

/*! open matching USB device and claim interface
 *  \param[in] ctx talloc context to use for related allocations
 *  \param[in] luctx libusb context on which to operate
 *  \param[in] ifm interface match describing interface to claim
 *  \returns libusb device chandle on success; NULL on error */
libusb_device_handle *osmo_libusb_open_claim_interface(void *ctx, libusb_context *luctx,
							const struct usb_interface_match *ifm)
{
	int rc, config;
	struct dev_id dev_ids[] = { { ifm->vendor, ifm->product }, { 0, 0 } };
	libusb_device **list;
	libusb_device **dev;
	libusb_device_handle *usb_devh = NULL;

	list = osmo_libusb_find_matching_usb_devs(ctx, luctx, dev_ids);
	if (!list) {
		perror("No USB device with matching VID/PID");
		return NULL;
	}

	for (dev = list; *dev; dev++) {
		int addr;
		char pathbuf[USB_MAX_PATH_LEN];
		char *path;

		addr = libusb_get_device_address(*dev);
		path = osmo_libusb_dev_get_path_buf(pathbuf, sizeof(pathbuf), *dev);
		if ((ifm->addr && addr == ifm->addr) ||
		    (strlen(ifm->path) && !strcmp(path, ifm->path)) ||
		    (!ifm->addr && !strlen(ifm->path) && !list[1] /* only one device */)) {
			rc = libusb_open(*dev, &usb_devh);
			if (rc < 0) {
				fprintf(stderr, "Cannot open device: %s\n", libusb_error_name(rc));
				usb_devh = NULL;
				break;
			}
			rc = libusb_get_configuration(usb_devh, &config);
			if (rc < 0) {
				fprintf(stderr, "Cannot get current configuration: %s\n", libusb_error_name(rc));
				libusb_close(usb_devh);
				usb_devh = NULL;
				break;
			}
			if (config != ifm->configuration) {
				rc = libusb_set_configuration(usb_devh, ifm->configuration);
				if (rc < 0) {
					fprintf(stderr, "Cannot set configuration: %s\n", libusb_error_name(rc));
					libusb_close(usb_devh);
					usb_devh = NULL;
					break;
				}
			}
			rc = libusb_claim_interface(usb_devh, ifm->interface);
			if (rc < 0) {
				fprintf(stderr, "Cannot claim interface: %s\n", libusb_error_name(rc));
				libusb_close(usb_devh);
				usb_devh = NULL;
				break;
			}
			rc = libusb_set_interface_alt_setting(usb_devh, ifm->interface, ifm->altsetting);
			if (rc < 0) {
				fprintf(stderr, "Cannot set interface altsetting: %s\n", libusb_error_name(rc));
				libusb_release_interface(usb_devh, ifm->interface);
				libusb_close(usb_devh);
				usb_devh = NULL;
				break;
			}
		}
	}

	/* unref / free list */
	for (dev = list; *dev; dev++)
		libusb_unref_device(*dev);
	talloc_free(list);

	return usb_devh;
}

void osmo_libusb_match_init(struct osmo_usb_matchspec *cfg, int if_class, int if_subclass, int if_proto)
{
	cfg->dev.vendor_id = -1;
	cfg->dev.product_id = -1;
	cfg->dev.path = NULL;

	cfg->config_id = -1;

	cfg->intf.class = if_class;
	cfg->intf.subclass = if_subclass;
	cfg->intf.proto = if_proto;

	cfg->intf.num = cfg->intf.altsetting = -1;
}


/*! high-level all-in-one function for USB device, config + interface matching + opening.
 * This function offers the highest level of API among all libosmousb helper functions. It
 * is intended as a one-stop shop for everything related to grabbing an interface.
 *
 *   1) looks for a device matching either the VID/PID from 'cfg' or 'default_dev_ids',
 *      if more than one is found, the user is expected to fill in cfg->dev.path to disambiguate.
 *   2) find any interfaces on the device that match the specification in 'cfg'. The match
 *      could be done based on any of (class, subclass, proto, interface number).  If there
 *      are multiple matches, the caller must disambiguate by specifying the interface number.
 *   3) open the USB device; set the configuration (if needed); claim the interface and set
 *      the altsetting
 *
 *  \param[in] cfg user-supplied match configuration (from command line or config file)
 *  \param[in] default_dev_ids Default list of supported VendorId/ProductIds
 *  \returns libusb_device_handle on success, NULL on error
 */
libusb_device_handle *osmo_libusb_find_open_claim(const struct osmo_usb_matchspec *cfg,
						  const struct dev_id *default_dev_ids)
{
	struct usb_interface_match if_matches[16];
	struct usb_interface_match *ifm = NULL;
	libusb_device_handle *usb_devh = NULL;
	struct dev_id user_dev_ids[2] = {
		{ cfg->dev.vendor_id, cfg->dev.product_id },
		{ 0, 0 }
	};
	const struct dev_id *dev_ids = default_dev_ids;
	libusb_device *dev;
	int rc, i;

	/* Stage 1: Find a device matching either the user-specified VID/PID or
	 * the list of IDs in default_dev_ids plus optionally the user-specified path */
	if (cfg->dev.vendor_id != -1 || cfg->dev.product_id != -1)
		dev_ids = user_dev_ids;
	dev = osmo_libusb_find_matching_dev_path(NULL, dev_ids, cfg->dev.path);
	if (!dev)
		goto close_exit;

	/* Stage 2: Find any interfaces matching the class/subclass/proto as specified */
	rc = osmo_libusb_dev_find_matching_interfaces(dev, cfg->intf.class, cfg->intf.subclass,
						      cfg->intf.proto, if_matches, sizeof(if_matches));
	if (rc < 1) {
		LOGP(DLUSB, LOGL_NOTICE, "can't find matching USB interface at device\n");
		goto close_exit;
	} else if (rc == 1) {
		ifm = if_matches;
	} else if (rc > 1) {
		if (cfg->intf.num == -1) {
			LOGP(DLUSB, LOGL_ERROR, "Found %d matching USB interfaces, you "
				"have to specify the interface number\n", rc);
			goto close_exit;
		}
		for (i = 0; i < rc; i++) {
			if (if_matches[i].interface == cfg->intf.num) {
				ifm = &if_matches[i];
				break;
			}
			/* FIXME: match altsetting */
		}
	}
	if (!ifm) {
		LOGP(DLUSB, LOGL_NOTICE, "Couldn't find matching interface\n");
		goto close_exit;
	}

	/* Stage 3: Open device; set config (if required); claim interface; set altsetting */
	usb_devh = osmo_libusb_open_claim_interface(NULL, NULL, ifm);
	if (!usb_devh) {
		LOGP(DLUSB, LOGL_ERROR, "can't open USB device (permissions issue?)\n");
		goto close_exit;
	}
	return usb_devh;
close_exit:
	/* release if_matches */
	if (usb_devh)
		libusb_close(usb_devh);

	return NULL;
}

/*! obtain the endpoint addresses for a given USB interface.
 *  \param[in] devh USB device handle on which to operate
 *  \param[in] if_num USB Interface number on which to operate
 *  \param[out] out user-provided storage for OUT endpoint number
 *  \param[out] in user-provided storage for IN endpoint number
 *  \param[out] irq user-provided storage for IRQ endpoint number
 *  \returns 0 in case of success; negative in case of error */
int osmo_libusb_get_ep_addrs(libusb_device_handle *devh, unsigned int if_num,
			     uint8_t *out, uint8_t *in, uint8_t *irq)
{
	libusb_device *dev = libusb_get_device(devh);
	struct libusb_config_descriptor *cdesc;
	const struct libusb_interface_descriptor *idesc;
	const struct libusb_interface *iface;
	int rc, l;

	rc = libusb_get_active_config_descriptor(dev, &cdesc);
	if (rc < 0)
		return rc;

	iface = &cdesc->interface[if_num];
	/* FIXME: we assume there's no altsetting */
	idesc = &iface->altsetting[0];

	for (l = 0; l < idesc->bNumEndpoints; l++) {
		const struct libusb_endpoint_descriptor *edesc = &idesc->endpoint[l];
		switch (edesc->bmAttributes & 3) {
		case LIBUSB_TRANSFER_TYPE_BULK:
			if (edesc->bEndpointAddress & 0x80) {
				if (in)
					*in = edesc->bEndpointAddress;
			} else {
				if (out)
					*out = edesc->bEndpointAddress;
			}
			break;
		case LIBUSB_TRANSFER_TYPE_INTERRUPT:
			if (irq)
				*irq = edesc->bEndpointAddress;
			break;
		default:
			break;
		}
	}
	return 0;
}
/***********************************************************************
 * initialization
 ***********************************************************************/

int osmo_libusb_init(libusb_context **pluctx)
{
	libusb_context *luctx = NULL;
	const struct libusb_pollfd **pfds;

	int rc;

	rc = libusb_init(pluctx);
	if (rc != 0) {
		LOGP(DLUSB, LOGL_ERROR, "Error initializing libusb: %s\n", libusb_strerror(rc));
		return rc;
	}

	if (pluctx)
		luctx = *pluctx;

#ifdef LIBUSB_LOG_CB_CONTEXT /* introduced in 1.0.23 */
	libusb_set_log_cb(luctx, &libosmo_usb_log_cb, LIBUSB_LOG_CB_CONTEXT);
#endif

	libusb_set_pollfd_notifiers(luctx, osmo_usb_added_cb, osmo_usb_removed_cb, luctx);

	/* get the initial file descriptors which were created even before during libusb_init() */
	pfds = libusb_get_pollfds(luctx);
	if (pfds) {
		const struct libusb_pollfd **pfds2 = pfds;
		const struct libusb_pollfd *pfd;
		/* synthesize 'add' call-backs. not sure why libusb doesn't do that by itself? */
		for (pfd = *pfds2; pfd; pfd = *++pfds2)
			osmo_usb_added_cb(pfd->fd, pfd->events, luctx);
		libusb_free_pollfds(pfds);
	}

	return 0;
}

void osmo_libusb_exit(libusb_context *luctx)
{
	/* we just assume libusb is cleaning up all the osmo_Fd's we've allocated */
	libusb_exit(luctx);
}
