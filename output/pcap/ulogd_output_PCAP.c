/* ulogd_PCAP.c, Version $Revision$
 *
 * ulogd output target for writing pcap-style files (like tcpdump)
 *
 * (C) 2002-2005 by Harald Welte <laforge@gnumonks.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <pcap.h>
#include <errno.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>

/* This is a timeval as stored on disk in a dumpfile.
 * It has to use the same types everywhere, independent of the actual
 * `struct timeval'
 */

struct pcap_timeval {
	int32_t tv_sec;
	int32_t tv_usec;
};

/*
 * How a `pcap_pkthdr' is actually stored in the dumpfile.
 *
 * Do not change the format of this structure, in any way (this includes
 * changes that only affect the length of fields in this structure),
 * and do not make the time stamp anything other than seconds and
 * microseconds (e.g., seconds and nanoseconds).  Instead:
 *
 *	introduce a new structure for the new format;
 *
 *	send mail to "tcpdump-workers@tcpdump.org", requesting a new
 *	magic number for your new capture file format, and, when
 *	you get the new magic number, put it in "savefile.c";
 *
 *	use that magic number for save files with the changed record
 *	header;
 *
 *	make the code in "savefile.c" capable of reading files with
 *	the old record header as well as files with the new record header
 *	(using the magic number to determine the header format).
 *
 * Then supply the changes to "patches@tcpdump.org", so that future
 * versions of libpcap and programs that use it (such as tcpdump) will
 * be able to read your new capture file format.
 */

struct pcap_sf_pkthdr {
	struct pcap_timeval ts;		/* time stamp */
	uint32_t caplen;		/* length of portion present */
	uint32_t len;			/* length this packet (off wire) */
};

#ifndef ULOGD_PCAP_DEFAULT
#define ULOGD_PCAP_DEFAULT	"/var/log/ulogd.pcap"
#endif

#ifndef ULOGD_PCAP_SYNC_DEFAULT
#define ULOGD_PCAP_SYNC_DEFAULT	0
#endif

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

static struct config_keyset pcap_kset = {
	.num_ces = 2,
	.ces = {
		{ 
			.key = "file", 
			.type = CONFIG_TYPE_STRING, 
			.options = CONFIG_OPT_NONE,
			.u = { .string = ULOGD_PCAP_DEFAULT },
		},
		{ 
			.key = "sync", 
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u = { .value = ULOGD_PCAP_SYNC_DEFAULT },
		},
	},
};

struct pcap_instance {
	FILE *of;
};

struct intr_id {
	char* name;
	unsigned int id;		
};

#define INTR_IDS 	7
static struct ulogd_key pcap_keys[INTR_IDS] = {
	{ .type = ULOGD_RET_UINT32,
	  .flags = ULOGD_RETF_NONE,
	  .name = "raw.pkt" },
	{ .type = ULOGD_RET_UINT32,
	  .flags = ULOGD_RETF_NONE,
	  .name = "raw.pktlen" },
	{ .type = ULOGD_RET_UINT16,
	  .flags = ULOGD_RETF_NONE,
	  .name = "ip.totlen" },
	{ .type = ULOGD_RET_UINT32,
	  .flags = ULOGD_RETF_NONE,
	  .name = "oob.time.sec" },
	{ .type = ULOGD_RET_UINT32,
	  .flags = ULOGD_RETF_NONE,
	  .name = "oob.time.usec" },
	{ .type = ULOGD_RET_UINT8,
	  .flags = ULOGD_RETF_NONE,
	  .name = "oob.family" },
	{ .type = ULOGD_RET_UINT16,
	  .flags = ULOGD_RETF_NONE,
	  .name = "ip6.payloadlen" },
};

#define GET_FLAGS(res, x)	(res[x].u.source->flags)

static int interp_pcap(struct ulogd_pluginstance *upi)
{
	struct pcap_instance *pi = (struct pcap_instance *) &upi->private;
	struct ulogd_key *res = upi->input.keys;
	struct pcap_sf_pkthdr pchdr;

	pchdr.caplen = ikey_get_u32(&res[1]);

	/* Try to set the len field correctly, if we know the protocol. */
	switch (ikey_get_u8(&res[5])) {
	case 2: /* INET */
		pchdr.len = ikey_get_u16(&res[2]);
		break;
	case 10: /* INET6 -- payload length + header length */
		pchdr.len = ikey_get_u16(&res[6]) + 40;
		break;
	default:
		pchdr.len = pchdr.caplen;
		break;
	}

	if (GET_FLAGS(res, 3) & ULOGD_RETF_VALID
	    && GET_FLAGS(res, 4) & ULOGD_RETF_VALID) {
		pchdr.ts.tv_sec = ikey_get_u32(&res[3]);
		pchdr.ts.tv_usec = ikey_get_u32(&res[4]);
	} else {
		/* use current system time */
		struct timeval tv;
		gettimeofday(&tv, NULL);

		pchdr.ts.tv_sec = tv.tv_sec;
		pchdr.ts.tv_usec = tv.tv_usec;
	}

	if (fwrite(&pchdr, sizeof(pchdr), 1, pi->of) != 1) {
		ulogd_log(ULOGD_ERROR, "Error during write: %s\n",
			  strerror(errno));
		return ULOGD_IRET_ERR;
	}
	if (fwrite(ikey_get_ptr(&res[0]), pchdr.caplen, 1, pi->of) != 1) {
		ulogd_log(ULOGD_ERROR, "Error during write: %s\n",
			  strerror(errno));
		return ULOGD_IRET_ERR;
	}

	if (upi->config_kset->ces[1].u.value)
		fflush(pi->of);

	return ULOGD_IRET_OK;
}

/* stolen from libpcap savefile.c */
#define LINKTYPE_RAW            101
#define TCPDUMP_MAGIC	0xa1b2c3d4

static int write_pcap_header(struct pcap_instance *pi)
{
	struct pcap_file_header pcfh;
	int ret;

	pcfh.magic = TCPDUMP_MAGIC;
	pcfh.version_major = PCAP_VERSION_MAJOR;
	pcfh.version_minor = PCAP_VERSION_MINOR;
	pcfh.thiszone = timezone;
	pcfh.sigfigs = 0;
	pcfh.snaplen = 64 * 1024; /* we don't know the length in advance */
	pcfh.linktype = LINKTYPE_RAW;

	ret =  fwrite(&pcfh, sizeof(pcfh), 1, pi->of);
	fflush(pi->of);

	return ret;
}

static int append_create_outfile(struct ulogd_pluginstance *upi)
{
	struct pcap_instance *pi = (struct pcap_instance *) &upi->private;
	char *filename = upi->config_kset->ces[0].u.string;
	struct stat st_of;
	FILE *of;

	of = fopen(filename, "a");
	if (!of) {
		ulogd_log(ULOGD_ERROR, "can't open pcap file %s: %s\n",
			  filename,
			  strerror(errno));
		return -EPERM;
	}

	if (pi->of)
		fclose(pi->of);
	pi->of = of;

	if (fstat(fileno(pi->of), &st_of) == 0 && st_of.st_size == 0 &&
	    !write_pcap_header(pi)) {
		ulogd_log(ULOGD_ERROR, "can't write pcap header: %s\n",
			  strerror(errno));
		return -ENOSPC;
	}

	return 0;
}

static void signal_pcap(struct ulogd_pluginstance *upi, int signal)
{
	switch (signal) {
	case SIGHUP:
		ulogd_log(ULOGD_NOTICE, "reopening capture file\n");
		append_create_outfile(upi);
		break;
	default:
		break;
	}
}

static int start_pcap(struct ulogd_pluginstance *upi)
{
	return append_create_outfile(upi);
}

static int stop_pcap(struct ulogd_pluginstance *upi)
{
	struct pcap_instance *pi = (struct pcap_instance *) &upi->private;

	if (pi->of)
		fclose(pi->of);

	return 0;
}

static struct ulogd_plugin pcap_plugin = {
	.name = "PCAP",
	.input = {
		.keys = pcap_keys,
		.num_keys = ARRAY_SIZE(pcap_keys),
		.type = ULOGD_DTYPE_PACKET,
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.config_kset	= &pcap_kset,
	.priv_size	= sizeof(struct pcap_instance),

	.start		= &start_pcap,
	.stop		= &stop_pcap,
	.signal		= &signal_pcap,
	.interp		= &interp_pcap,
	.version	= VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&pcap_plugin);
}
