#ifndef _ULOGD_H
#define _ULOGD_H
/* ulogd
 *
 * Userspace logging daemon for netfilter/iptables
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
 *
 * this code is released under the terms of GNU GPL
 *
 */

#include <ulogd/linuxlist.h>
#include <ulogd/conffile.h>
#include <ulogd/ipfix_protocol.h>
#include <stdio.h>
#include <signal.h>	/* need this because of extension-sighandler */
#include <sys/types.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <string.h>
#include <config.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/*
 * Minimum size of buffer required to hold an ipv6 address encoded as a
 * hex-string, e.g.:
 *
 *                          ::1 -> "0x00000000000000000000000000000001"
 * 2600:1408:ec00:36::1736:7f28 -> "0x26001408ec0000360000000017367f28"
 */
#define FORMAT_IPV6_BUFSZ (2 + sizeof(struct in6_addr) * 2 + 1)

/* All types with MSB = 1 make use of value.ptr
 * other types use one of the union's member */

/* types without length */
#define ULOGD_RET_NONE		0x0000

#define ULOGD_RET_INT8		0x0001
#define ULOGD_RET_INT16		0x0002
#define ULOGD_RET_INT32		0x0003
#define ULOGD_RET_INT64		0x0004

#define ULOGD_RET_UINT8		0x0011
#define ULOGD_RET_UINT16	0x0012
#define ULOGD_RET_UINT32	0x0013
#define ULOGD_RET_UINT64	0x0014

#define ULOGD_RET_BOOL		0x0050

#define ULOGD_RET_IPADDR	0x0100
#define ULOGD_RET_IP6ADDR	0x0200

/* types with length field */
#define ULOGD_RET_STRING	0x8020
#define ULOGD_RET_RAW		0x8030
#define ULOGD_RET_RAWSTR	0x8040


/* FLAGS */
#define ULOGD_RETF_NONE		0x0000
#define ULOGD_RETF_VALID	0x0001	/* contains a valid result */
#define ULOGD_RETF_FREE		0x0002	/* ptr needs to be free()d */
#define ULOGD_RETF_NEEDED	0x0004	/* this parameter is actually needed
					 * by some downstream plugin */

#define ULOGD_KEYF_OPTIONAL	0x0100	/* this key is optional */
#define ULOGD_KEYF_INACTIVE	0x0200	/* marked as inactive (i.e. totally
					   to be ignored by everyone */


/* maximum length of ulogd key */
#define ULOGD_MAX_KEYLEN 31

#define ULOGD_DEBUG	1	/* debugging information */
#define ULOGD_INFO	3
#define ULOGD_NOTICE	5	/* abnormal/unexpected condition */
#define ULOGD_ERROR	7	/* error condition, requires user action */
#define ULOGD_FATAL	8	/* fatal, program aborted */

/* ulogd data type */
enum ulogd_dtype {
	ULOGD_DTYPE_NULL	= 0x0000,
	ULOGD_DTYPE_SOURCE	= 0x0001, /* source of data, no input keys */
	ULOGD_DTYPE_RAW		= 0x0002, /* raw packet data */
	ULOGD_DTYPE_PACKET	= 0x0004, /* packet metadata */
	ULOGD_DTYPE_FLOW	= 0x0008, /* flow metadata */
	ULOGD_DTYPE_SUM		= 0x0010, /* sum metadata */
	ULOGD_DTYPE_SINK	= 0x0020, /* sink of data, no output keys */
};

/* structure describing an input  / output parameter of a plugin */
struct ulogd_key {
	/* length of the returned value (only for lengthed types */
	uint32_t len;
	/* type of the returned value (ULOGD_DTYPE_...) */
	uint16_t type;
	/* flags (i.e. free, ...) */
	uint16_t flags;
	/* name of this key */
	char name[ULOGD_MAX_KEYLEN+1];
	/* IETF IPFIX attribute ID */
	struct {
		uint32_t	vendor;
		uint16_t	field_id;
	} ipfix;

	/* Store field name for Common Information Model */
	char *cim_name;

	union {
		/* and finally the returned value */
		union {
			uint8_t	b;
			uint8_t	ui8;
			uint16_t	ui16;
			uint32_t	ui32;
			uint64_t	ui64;
			uint32_t	ui128[4];
			int8_t		i8;
			int16_t		i16;
			int32_t		i32;
			int64_t		i64;
			int32_t		i128[4];
			void		*ptr;
		} value;
		struct ulogd_key *source;
	} u;
};

struct ulogd_keyset {
	/* possible input keys of this interpreter */
	struct ulogd_key *keys;
	/* number of input keys */
	unsigned int num_keys;
	/* bitmask of possible types */
	unsigned int type;
};

static inline void okey_set_b(struct ulogd_key *key, uint8_t value)
{
	key->u.value.b = value;
	key->flags |= ULOGD_RETF_VALID;
	key->len = sizeof(key->u.value.b);
}

static inline void okey_set_u8(struct ulogd_key *key, uint8_t value)
{
	key->u.value.ui8 = value;
	key->flags |= ULOGD_RETF_VALID;
	key->len = sizeof(key->u.value.ui8);
}

static inline void okey_set_u16(struct ulogd_key *key, uint16_t value)
{
	key->u.value.ui16 = value;
	key->flags |= ULOGD_RETF_VALID;
	key->len = sizeof(key->u.value.ui16);
}

static inline void okey_set_u32(struct ulogd_key *key, uint32_t value)
{
	key->u.value.ui32 = value;
	key->flags |= ULOGD_RETF_VALID;
	key->len = sizeof(key->u.value.ui32);
}

static inline void okey_set_u64(struct ulogd_key *key, uint64_t value)
{
	key->u.value.ui64 = value;
	key->flags |= ULOGD_RETF_VALID;
	key->len = sizeof(key->u.value.ui64);
}

static inline void okey_set_u128(struct ulogd_key *key, const void *value)
{
	memcpy(key->u.value.ui128, value, sizeof(key->u.value.ui128));
	key->flags |= ULOGD_RETF_VALID;
	key->len = sizeof(key->u.value.ui128);
}

static inline void okey_set_ptr(struct ulogd_key *key, void *value)
{
	key->u.value.ptr = value;
	key->flags |= ULOGD_RETF_VALID;
}

static inline uint8_t ikey_get_u8(struct ulogd_key *key)
{
	return key->u.source->u.value.ui8;
}

static inline uint16_t ikey_get_u16(struct ulogd_key *key)
{
	return key->u.source->u.value.ui16;
}

static inline uint32_t ikey_get_u32(struct ulogd_key *key)
{
	return key->u.source->u.value.ui32;
}

static inline uint64_t ikey_get_u64(struct ulogd_key *key)
{
	return key->u.source->u.value.ui64;
}

static inline void *ikey_get_u128(struct ulogd_key *key)
{
	return &key->u.source->u.value.ui128;
}

static inline void *ikey_get_ptr(struct ulogd_key *key)
{
	return key->u.source->u.value.ptr;
}

/**
 * Convert IPv4 address (as 32-bit unsigned integer) to IPv6 address: add 96-bit
 * prefix "::ffff" to get IPv6 address "::ffff:a.b.c.d".
 */
static inline struct in6_addr *
uint32_to_ipv6(uint32_t ipv4, struct in6_addr *ipv6)
{
	static const uint8_t IPV4_IN_IPV6_PREFIX[12] = {
		[10] = 0xff,
		[11] = 0xff,
	};
	uint8_t *p = ipv6->s6_addr;

	memcpy(p, IPV4_IN_IPV6_PREFIX, sizeof(IPV4_IN_IPV6_PREFIX));
	p += sizeof(IPV4_IN_IPV6_PREFIX);
	memcpy(p, &ipv4, sizeof(ipv4));

	return ipv6;
}

static inline void
format_ipv6(char *buf, size_t size, const struct in6_addr *ipv6)
{
	unsigned i = 0;

	if (size >= FORMAT_IPV6_BUFSZ) {
		buf[i++] = '0';
		buf[i++] = 'x';

		for (unsigned j = 0; i < sizeof(*ipv6); j += 4, i += 8) {
			sprintf(buf + i, "%02hhx%02hhx%02hhx%02hhx",
				ipv6->s6_addr[j + 0],
				ipv6->s6_addr[j + 1],
				ipv6->s6_addr[j + 2],
				ipv6->s6_addr[j + 3]);
		}
	}
	buf[i] = '\0';
}

struct ulogd_pluginstance_stack;
struct ulogd_pluginstance;

struct ulogd_plugin_handle {
	/* global list of plugins */
	struct llist_head list;
	void *handle;
};


struct ulogd_plugin {
	/* global list of plugins */
	struct llist_head list;
	/* version */
	char *version;
	/* name of this plugin (predefined by plugin) */
	char name[ULOGD_MAX_KEYLEN+1];
	/* ID for this plugin (dynamically assigned) */
	unsigned int id;
	/* how many stacks are using this plugin? initially set to zero. */
	unsigned int usage;

	struct ulogd_keyset input;
	struct ulogd_keyset output;

	/* function to call for each packet */
	int (*interp)(struct ulogd_pluginstance *instance);

	int (*configure)(struct ulogd_pluginstance *instance,
			 struct ulogd_pluginstance_stack *stack);

	/* function to construct a new pluginstance */
	int (*start)(struct ulogd_pluginstance *pi);
	/* function to destruct an existing pluginstance */
	int (*stop)(struct ulogd_pluginstance *pi);

	/* function to receive a signal */
	void (*signal)(struct ulogd_pluginstance *pi, int signal);

	/* configuration parameters */
	struct config_keyset *config_kset;

	/* size of instance->priv */
	unsigned int priv_size;
};

#define ULOGD_IRET_ERR		-1
#define ULOGD_IRET_STOP		-2
#define ULOGD_IRET_OK		0

/* an instance of a plugin, element in a stack */
struct ulogd_pluginstance {
	/* local list of plugins in this stack */
	struct llist_head list;
	/* local list of plugininstance in other stacks */
	struct llist_head plist;
	/* plugin */
	struct ulogd_plugin *plugin;
	/* stack that we're part of */
	struct ulogd_pluginstance_stack *stack;
	/* name / id  of this instance*/
	char id[ULOGD_MAX_KEYLEN+1];
	/* per-instance input keys */
	struct ulogd_keyset input;
	/* per-instance output keys */
	struct ulogd_keyset output;
	/* per-instance config parameters (array) */
	struct config_keyset *config_kset;
	/* private data */
	char private[0];
};

struct ulogd_pluginstance_stack {
	/* global list of pluginstance stacks */
	struct llist_head stack_list;
	/* list of plugins in this stack */
	struct llist_head list;
	char *name;
};

/***********************************************************************
 * PUBLIC INTERFACE 
 ***********************************************************************/

void ulogd_propagate_results(struct ulogd_pluginstance *pi);

/* register a new interpreter plugin */
void ulogd_register_plugin(struct ulogd_plugin *me);

/* allocate a new ulogd_key */
struct ulogd_key *alloc_ret(const uint16_t type, const char*);

/* write a message to the daemon's logfile */
void __ulogd_log(int level, char *file, int line, const char *message, ...)
	__attribute__((format(printf, 4, 5)));
/* macro for logging including filename and line number */
#define ulogd_log(level, format, args...) \
	__ulogd_log(level, __FILE__, __LINE__, format, ## args)
/* backwards compatibility */
#define ulogd_error(format, args...) ulogd_log(ULOGD_ERROR, format, ## args)

#define IS_VALID(x)	((x).flags & ULOGD_RETF_VALID)
#define SET_VALID(x)	(x.flags |= ULOGD_RETF_VALID)
#define IS_NEEDED(x)	(x.flags & ULOGD_RETF_NEEDED)
#define SET_NEEDED(x)	(x.flags |= ULOGD_RETF_NEEDED)

#define GET_FLAGS(res, x)	(res[x].u.source->flags)
#define GET_LENGTH(res, x)	(res[x].u.source->len)
#define pp_is_valid(res, x)	\
	(res[x].u.source && (GET_FLAGS(res, x) & ULOGD_RETF_VALID))

int ulogd_key_size(struct ulogd_key *key);
int ulogd_wildcard_inputkeys(struct ulogd_pluginstance *upi);
int ulogd_parse_configfile(const char *section, struct config_keyset *ce);

/***********************************************************************
 * file descriptor handling
 ***********************************************************************/

#define ULOGD_FD_READ	0x0001
#define ULOGD_FD_WRITE	0x0002
#define ULOGD_FD_EXCEPT	0x0004

struct ulogd_fd {
	struct llist_head list;
	int fd;				/* file descriptor */
	unsigned int when;
	int (*cb)(int fd, unsigned int what, void *data);
	void *data;			/* void * to pass to callback */
};

int ulogd_register_fd(struct ulogd_fd *ufd);
void ulogd_unregister_fd(struct ulogd_fd *ufd);
int ulogd_select_main(struct timeval *tv);

/***********************************************************************
 * timer handling
 ***********************************************************************/
#include <ulogd/timer.h>

/***********************************************************************
 * other declarations
 ***********************************************************************/

#ifndef IPPROTO_DCCP
#define IPPROTO_DCCP 33
#endif

#ifndef IPPROTO_UDPLITE
#define IPPROTO_UDPLITE 136
#endif

#endif /* _ULOGD_H */
