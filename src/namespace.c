// SPDX-License-Identifier: GPL-2.0
/* ulogd namespace helper
 *
 * (C) 2025 The netfilter project
 *
 * Helper library to switch linux namespaces, primarily network. Provides
 * ulogd-internally a stable api regardless whether namespace support is
 * compiled in. Library-internally uses conditional compilation to allow the
 * wanted level (full/none) of namespace support. Namespaces can be specified
 * as open file descriptor or file path.
 */

#include "config.h"

/* Enable GNU extension */
#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <string.h>
#include <unistd.h>

#include "ulogd/ulogd.h"
#include "ulogd/namespace.h"


#ifdef ENABLE_NAMESPACE
/**
 * open_namespace_path() - Open a namespace link by path.
 * @ns_path: Path of the file to open.
 *
 * Effectively just a wrapper around the open() syscall with fixed flags
 * suitable for namespaces.
 *
 * Return: Open fd on success, -1 on error (and set errno).
 */
static int open_namespace_path(const char *const ns_path) {
	return open(ns_path, O_RDONLY | O_CLOEXEC);
}

/**
 * SELF_NAMESPACE_PATH() - Path for own current namespace.
 * @x: Name of the namespace link.
 *
 * Return: String-constant of the absolute path to the namespace link.
 */
#define SELF_NAMESPACE_PATH(x) "/proc/self/ns/" #x

/**
 * open_source_namespace() - Get file descriptor to current namespace.
 * @nstype: Namespace type, use one of the CLONE_NEW* constants.
 *
 * Return: Open fd on success, -1 on error.
 */
static int open_source_namespace(const int nstype) {
	const char *ns_path = NULL;
	int ns_fd = -1;

	switch (nstype) {
	case CLONE_NEWNET:
		ns_path = SELF_NAMESPACE_PATH(net);
		break;
	default:
		ulogd_log(ULOGD_FATAL,
		          "unsupported namespace type: %d\n", nstype);
		return -1;
	}

	ns_fd = open_namespace_path(ns_path);
	if (ns_fd < 0) {
		ulogd_log(ULOGD_FATAL,
		          "error opening namespace '%s': %s\n",
		          ns_path, strerror(errno));
		return -1;
	}

	return ns_fd;
}
#else

/* These constants are used by the nstype-specific functions, and need to be
 * defined even when no namespace support is available because only the generic
 * functions will error.
 */
#ifndef CLONE_NEWNET
#define CLONE_NEWNET -1
#endif

#endif /* ENABLE_NAMESPACE */

/**
 * join_namespace_fd() - Join a namespace by file descriptor.
 * @nstype: Namespace type, use one of the CLONE_NEW* constants.
 * @target_ns_fd: Open file descriptor of the namespace to join. Will be closed
 *                after successful join.
 * @source_ns_fd_ptr: If not NULL, writes an open fd of the previous namespace
 *                    to it if join was successful. May point to negative value
 *                    after return.
 *
 * Return: ULOGD_IRET_OK on success, ULOGD_IRET_ERR otherwise.
 */
static int join_namespace_fd(const int nstype, const int target_ns_fd,
                             int *const source_ns_fd_ptr)
{
#ifdef ENABLE_NAMESPACE
	if (target_ns_fd < 0) {
		ulogd_log(ULOGD_DEBUG, "invalid target namespace fd\n");
		return ULOGD_IRET_ERR;
	}

	if (source_ns_fd_ptr != NULL) {
		*source_ns_fd_ptr = open_source_namespace(nstype);
		if (*source_ns_fd_ptr < 0) {
			ulogd_log(ULOGD_FATAL,
			          "error opening source namespace\n");
			return ULOGD_IRET_ERR;
		}
	}

	if (setns(target_ns_fd, nstype) < 0) {
		ulogd_log(ULOGD_FATAL, "error joining target namespace: %s\n",
		          strerror(errno));

		if (source_ns_fd_ptr != NULL) {
			if (close(*source_ns_fd_ptr) < 0) {
				ulogd_log(ULOGD_NOTICE,
				          "error closing source namespace: %s\n",
				          strerror(errno));
			}
			*source_ns_fd_ptr = -1;
		}

		return ULOGD_IRET_ERR;
	}
	ulogd_log(ULOGD_DEBUG, "successfully switched namespace\n");

	if (close(target_ns_fd) < 0) {
		ulogd_log(ULOGD_NOTICE, "error closing target namespace: %s\n",
		          strerror(errno));
	}

	return ULOGD_IRET_OK;
#else
	if (source_ns_fd_ptr != NULL) {
		*source_ns_fd_ptr = -1;
	}
	ulogd_log(ULOGD_FATAL,
	          "ulogd was compiled without linux namespace support.\n");
	return ULOGD_IRET_ERR;
#endif /* ENABLE_NAMESPACE */
}

/**
 * join_namespace_path() - Join a namespace by path.
 * @nstype: Namespace type, use one of the CLONE_NEW* constants.
 * @target_ns_path: Path of the namespace to join.
 * @source_ns_fd_ptr: If not NULL, writes an open fd of the previous namespace
 *                    to it if join was successful. May point to negative value
 *                    after return.
 *
 * Return: ULOGD_IRET_OK on success, ULOGD_IRET_ERR otherwise.
 */
static int join_namespace_path(const int nstype, const char *const target_ns_path,
                               int *const source_ns_fd_ptr)
{
#ifdef ENABLE_NAMESPACE
	int target_ns_fd, ret;

	target_ns_fd = open_namespace_path(target_ns_path);
	if (target_ns_fd < 0) {
		ulogd_log(ULOGD_FATAL, "error opening target namespace: %s\n",
		          strerror(errno));
		return ULOGD_IRET_ERR;
	}

	ret = join_namespace_fd(nstype, target_ns_fd, source_ns_fd_ptr);
	if (ret != ULOGD_IRET_OK) {
		if (close(target_ns_fd) < 0) {
			ulogd_log(ULOGD_NOTICE,
			          "error closing target namespace: %s\n",
			          strerror(errno));
		}
		return ULOGD_IRET_ERR;
	}

	return ULOGD_IRET_OK;
#else
	return join_namespace_fd(nstype, -1, source_ns_fd_ptr);
#endif /* ENABLE_NAMESPACE */
}


/**
 * join_netns_fd() - Join a network namespace by file descriptor.
 * @target_netns_fd: Open file descriptor of the network namespace to join. Will
 *                   be closed after successful join.
 * @source_netns_fd_ptr: If not NULL, writes an open fd of the previous network
 *                       namespace to it if join was successful. May point to
 *                       negative value after return.
 *
 * Return: ULOGD_IRET_OK on success, ULOGD_IRET_ERR otherwise.
 */
int join_netns_fd(const int target_netns_fd, int *const source_netns_fd_ptr)
{
	return join_namespace_fd(CLONE_NEWNET, target_netns_fd,
	                         source_netns_fd_ptr);
}

/**
 * join_netns_path() - Join a network namespace by path.
 * @target_netns_path: Path of the network namespace to join.
 * @source_netns_fd_ptr: If not NULL, writes an open fd of the previous network
 *                       namespace to it if join was successful. May point to
 *                       negative value after return.
 *
 * Return: ULOGD_IRET_OK on success, ULOGD_IRET_ERR otherwise.
 */
int join_netns_path(const char *const target_netns_path,
                    int *const source_netns_fd_ptr)
{
	return join_namespace_path(CLONE_NEWNET, target_netns_path,
	                           source_netns_fd_ptr);
}
