/*****************************************************************************
 * ip.c
 *
 * Build and manipulate IP and networks.
 *
 * ---------------------------------------------------------------------------
 * libip - IP address manipulation library
 *   (C) 2013 Gerardo Garc�a Pe�a <killabytenow@gmail.com>
 *
 *   This program is free software; you can redistribute it and/or modify it
 *   under the terms of the GNU General Public License as published by the Free
 *   Software Foundation; either version 2 of the License, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful, but WITHOUT
 *   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *   FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 *   more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc., 51
 *   Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 *****************************************************************************/

#include "autoconfig.h"

#if HAVE_STRING_H
#  include <string.h>
#else
#  if HAVE_STRINGS_H
#    include <strings.h>
#  endif
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "libip.h"

#define IPV4_GETP(p,x)  ((unsigned char) ((ntohl((x)->addr) >> ((p)*8)) & 0x000000ffl))
#define IPV6_GETB(p,x)  ((unsigned char) ((x)->addr[(p)]))

static int ip_read(char *network, char *s, INET_IPV4_ADDR_T *addr, INET_IPV4_ADDR_T rest)
{
	char *s2;
	int i, num;
	INET_IPV4_ADDR_T netmask = 0xFFFFFFFFl;

	*addr = 0;
	for(i = 0; s && i < 4; i++) {
		s2 = strchr(s, '.');
		if(s2)
			*s2++ = '\0';
		sscanf(s, "%d", &num);
		if(num < 0 || num > 255) {
			errno = EINVAL; /* Bad component in address */
			return -1;
		}

		*addr = (*addr) << 8;
		*addr = (*addr) | num;
		netmask <<= 8;
		s = s2;
	}
	if(i < 4) {
		if(!rest) {
			errno = EINVAL; /* Need more components in address */
			return -1;
		} else
			*addr = (rest & netmask) | *addr;
	} else {
		if(s)
		{
			errno = EINVAL; /* Too much components in address */
			return -1;
		}
	}

	errno = 0; /* ok */
	return 0;
}

static int ip_read_network(char *network, char *s, INET_IPV4_RANGE *range)
{
	char *s2;
	int bits;
	INET_IPV4_ADDR_T netmask, addr;

	s2 = strrchr(s, '/');
	*s2++ = '\0';
	sscanf(s2, "%d", &bits);
	if(bits < 0 || bits > 32) {
		errno = EINVAL; /* Bad network address */
		return -1;
	}
	netmask = (0xffffffffL << (32 - bits));
	if(ip_read(network, s, &addr, 0))
		return -1;

	range->first_addr = (addr &  netmask);
	range->last_addr  = (addr | ~netmask);

	errno = 0; /* ok */
	return 0;
}

static int ip_read_addr_range(char *network, char *s, INET_IPV4_RANGE *range)
{
	char *s2;
	INET_IPV4_ADDR_T addr;

	s2 = strchr(s, '-');
	*s2++ = '\0';
	if(ip_read(network, s,  &(range->first_addr), 0))
		return -1;
	if(ip_read(network, s2, &(range->last_addr), range->first_addr))
		return -1;

	if(range->first_addr > range->last_addr) {
		addr = range->first_addr;
		range->first_addr = range->last_addr;
		range->last_addr = addr;
	}

	errno = 0; /* ok */
	return 0;
}

int ip_read_range(char *network, INET_IPV4_RANGE *range)
{
	char *s;
	int ret = 0, __errno;

	if((s = strdup(network)) == NULL) {
		errno = ENOMEM; /* No memory for network */
		return -1;
	}

	if(strrchr(s, '/') != NULL)
		ret = ip_read_network(network, s, range);
	else if(strchr(s, '-') != NULL)
		ret = ip_read_addr_range(network, s, range);
	else {
		ret = ip_read(network, s, &(range->first_addr), 0);
		range->last_addr = range->first_addr;
	}
	/* free mem and save 'errno' from a potential buggy implementation */
	__errno = errno;
	free(s);

	errno = __errno;
	return ret;
}

int ip_bigsockaddr_to_addr(BIGSOCKADDR *saddr, INET_ADDR *addr, int *port)
{
	switch(saddr->sa.sa_family) {
	case AF_INET:
		addr->in.addr = saddr->in.sin_addr.s_addr;
		addr->type = INET_FAMILY_IPV4;
		if(port)
			*port = saddr->in.sin_port;
		break;
	case AF_INET6:
#if HAVE_STRUCT_SOCKADDR_IN6
		memcpy(addr->in6.addr, &saddr->in6.sin6_addr, sizeof(addr->in6));
		addr->type = INET_FAMILY_IPV6;
		if(port)
			*port = saddr->in6.sin6_port;
		break;
#else
		errno = EAFNOSUPPORT;
		return -1;
#endif
	default:
		errno = EAFNOSUPPORT; /* Unknown internet protocol */
		return -1;
	}

	errno = 0; /* ok */
	return 0;
}

int ip_addr_to_bigsockaddr(INET_ADDR *addr, int port, BIGSOCKADDR *saddr)
{
	/* fill sockaddr structure */
	switch(addr->type)
	{
	case INET_FAMILY_IPV4:
		saddr->in.sin_addr.s_addr = addr->in.addr;
		saddr->in.sin_family = AF_INET;
		saddr->in.sin_port = htons(port);
		memset(&(saddr->in.sin_zero), 0, 8);
		saddr->size = sizeof(struct sockaddr_in);
		break;
	case INET_FAMILY_IPV6:
#if HAVE_STRUCT_SOCKADDR_IN6
		saddr->size = sizeof(struct sockaddr_in6);
#ifdef SIN6_LEN
		saddr->in6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		saddr->in6.sin6_family = AF_INET6;
		saddr->in6.sin6_flowinfo = 0;
		saddr->in6.sin6_port = htons(port);
		memcpy(&saddr->in6.sin6_addr, addr->in6.addr, sizeof(addr->in6));
		break;
#else
		errno = EAFNOSUPPORT; /* This platform does not support IPv6 */
		return -1;
#endif
	default:
		errno = EAFNOSUPPORT; /* Unknown internet protocol */
		return -1;
	}

	errno = 0; /* ok */
	return 0;
}

int ip_bigsockaddr_get_socket(BIGSOCKADDR *saddr, int type, int protocol)
{
	return socket(saddr->sa.sa_family, type, protocol);
}

void ip_addr_set_null(INET_ADDR *addr)
{
	memset(addr, 0, sizeof(INET_ADDR));
}

void ip_addr_set_ipv4(INET_ADDR *addr, INET_IPV4_ADDR *in)
{
	addr->type = INET_FAMILY_IPV4;
	memcpy(&addr->in, in, sizeof(INET_IPV4_ADDR));
}

void ip_addr_set_ipv6(INET_ADDR *addr, INET_IPV6_ADDR *in6)
{
	addr->type = INET_FAMILY_IPV6;
	memcpy(&addr->in6, in6, sizeof(INET_IPV6_ADDR));
}

void ip_addr_copy(INET_ADDR *to, INET_ADDR *from)
{
	memcpy(to, from, sizeof(INET_ADDR));
}

int ip_addr_snprintf_ipv4(INET_ADDR *addr, int port, int l, char *str)
{
	if(addr->type == INET_FAMILY_IPV4) {
		errno = 0; /* ok */
		return port >= 0
			? snprintf(str, l, "%u.%u.%u.%u:%u",
				IPV4_GETP(3, &addr->in),
				IPV4_GETP(2, &addr->in),
				IPV4_GETP(1, &addr->in),
				IPV4_GETP(0, &addr->in),
				port)
			: snprintf(str, l, "%u.%u.%u.%u",
				IPV4_GETP(3, &addr->in),
				IPV4_GETP(2, &addr->in),
				IPV4_GETP(1, &addr->in),
				IPV4_GETP(0, &addr->in));
	}

	/* It is not an IPv4 address */
	errno = EINVAL;
	return -1;
}

int ip_addr_snprintf_ipv6(INET_ADDR *addr, int port, int l, char *str)
{
	if(addr->type == INET_FAMILY_IPV6) {
		errno = 0; /* ok */
		return snprintf(str, l,
				"%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
				"%02x%02x:%02x%02x:%02x%02x:%02x%02x",
				IPV6_GETB( 0, &addr->in6), IPV6_GETB( 1, &addr->in6),
				IPV6_GETB( 2, &addr->in6), IPV6_GETB( 3, &addr->in6),
				IPV6_GETB( 4, &addr->in6), IPV6_GETB( 5, &addr->in6),
				IPV6_GETB( 6, &addr->in6), IPV6_GETB( 7, &addr->in6),
				IPV6_GETB( 8, &addr->in6), IPV6_GETB( 9, &addr->in6),
				IPV6_GETB(10, &addr->in6), IPV6_GETB(11, &addr->in6),
				IPV6_GETB(12, &addr->in6), IPV6_GETB(13, &addr->in6),
				IPV6_GETB(14, &addr->in6), IPV6_GETB(15, &addr->in6));
	}

	/* It is not an IPv6 address */
	errno = EINVAL;
	return -1;
}

int ip_addr_snprintf(INET_ADDR *addr, int port, int l, char *str)
{
	switch(addr->type) {
	case INET_FAMILY_IPV4:
		return ip_addr_snprintf_ipv4(addr, port, l, str);
	case INET_FAMILY_IPV6:
		return ip_addr_snprintf_ipv6(addr, port, l, str);
	default:
		return snprintf(str, l, "<NO-ADDRESS>");
	}
}

int ip_snprintf_ipv4(INET_IPV4_ADDR *in, int port, int l, char *str)
{
	return snprintf(str, l, "%u.%u.%u.%u",
			IPV4_GETP(3, in),
			IPV4_GETP(2, in),
			IPV4_GETP(1, in),
			IPV4_GETP(0, in));
}

int ip_snprintf_ipv6(INET_IPV6_ADDR *in6, int port, int l, char *str)
{
	return snprintf(str, l,
			"%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
			"%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			IPV6_GETB( 0, in6), IPV6_GETB( 1, in6),
			IPV6_GETB( 2, in6), IPV6_GETB( 3, in6),
			IPV6_GETB( 4, in6), IPV6_GETB( 5, in6),
			IPV6_GETB( 6, in6), IPV6_GETB( 7, in6),
			IPV6_GETB( 8, in6), IPV6_GETB( 9, in6),
			IPV6_GETB(10, in6), IPV6_GETB(11, in6),
			IPV6_GETB(12, in6), IPV6_GETB(13, in6),
			IPV6_GETB(14, in6), IPV6_GETB(15, in6));
}

int ip_addr_parse_ipv4(char *saddr, INET_ADDR *addr, int *port)
{
	int a, b, c, d, p, r, x, port_defined;

	if((r = sscanf(saddr, "%3u.%3u.%3u.%3u:%5u%n", &a, &b, &c, &d, &p, &x)) != 5)
		if((r = sscanf(saddr, "%3u.%3u.%3u.%3u%n", &a, &b, &c, &d, &x)) != 4)
			if((r = sscanf(saddr, "%2x%2x%2x%2x%n", &d, &c, &b, &a, &x)) != 4) {
				errno = EINVAL;
				return -1;
			}

	if(r == 4) {
		p = 0;
		port_defined = 0;
	} else
		port_defined = 1;
	if(saddr[x]) {
		errno = ENOMEM;
		return -1;
	}

	if(a < 0 || a > 255
	|| b < 0 || b > 255
	|| c < 0 || c > 255
	|| d < 0 || d > 255
	|| p < 0 || p > 0x0000ffffl) {
		errno = EINVAL;
		return -1;
	}

	addr->type = INET_FAMILY_IPV4;
	addr->in.addr = htonl(
			((d & 0x000000ffl) <<  0)
			| ((c & 0x000000ffl) <<  8)
			| ((b & 0x000000ffl) << 16)
			| ((a & 0x000000ffl) << 24));

	if(port_defined) {
		if(!port) {
			errno = EINVAL;
			return -1; /* port set, but not accepted */
		}
		*port = port_defined ?  p : -1;
	}

	errno = 0; /* ok */
	return 0;
}

int ip_addr_parse_ipv6(char *saddr, INET_ADDR *addr, int *port)
{
	errno = ENOSYS; /* TODO: Function not implemented */
	return -1;
}

int ip_addr_parse(char *saddr, INET_ADDR *addr, int *port)
{
	if(!ip_addr_parse_ipv4(saddr, addr, port))
		return 0;
	if(!ip_addr_parse_ipv6(saddr, addr, port))
		return 0;

	memset(addr, 0, sizeof(INET_ADDR));
	errno = EINVAL;
	return -1;
}

int ip_addr_get_part_ipv4(INET_ADDR *addr, int part)
{
	if(addr->type != INET_FAMILY_IPV4 || part < 1 || part > 4) {
		errno = EINVAL; /* Bad IPv4 address or invalid part number */
		return -1;
	}

	errno = 0; /* ok */
	return IPV4_GETP(part-1, &addr->in);
}

int ip_addr_get_part_ipv6_nibble(INET_ADDR *addr, int part)
{
	int byte, desp;

	if(addr->type != INET_FAMILY_IPV6 || part < 1 || part > 32) {
		errno = EINVAL; /* Bad IPv6 address or invalid nibble-part number */
		return -1;
	}

	byte = (part - 1) >> 1;
	desp = (part - 1) & 1 ? 0 : 4;

	errno = 0; /* ok */
	return ((IPV6_GETB(byte, &addr->in6) >> desp) & 0x0f);
}

int ip_addr_get_part_ipv6_byte(INET_ADDR *addr, int part)
{
	if(addr->type != INET_FAMILY_IPV6 || part < 1 || part > 16) {
		errno = EINVAL; /* Bad IPv6 address or invalid byte-part number */
		return -1;
	}

	errno = 0; /* ok */
	return IPV6_GETB(part - 1, &addr->in6);
}

int ip_addr_get_part_ipv6_word(INET_ADDR *addr, int part)
{
	if(addr->type != INET_FAMILY_IPV6 || part < 1 || part > 8) {
		errno = EINVAL; /* Bad IPv6 address or invalid word-part number */
		return -1;
	}

	errno = 0; /* ok */
	return (IPV6_GETB(((part - 1) * 2) + 0, &addr->in6) << 8
		| IPV6_GETB(((part - 1) * 2) + 1, &addr->in6));
}

int ip_addr_check_mask(INET_ADDR *addr, INET_ADDR *netw, INET_ADDR *mask)
{
	int i;

	/* be optimistic */
	errno = 0;

	/* check compatibility */
	if(addr->type != netw->type)
		return 0;

	/* check mask */
	switch(addr->type) {
	case INET_FAMILY_NONE:
		return 0;
	case INET_FAMILY_IPV4:
		return (netw->in.addr & mask->in.addr)
			== (addr->in.addr & mask->in.addr);
	case INET_FAMILY_IPV6:
		for(i = 15; i >= 0 && mask->in6.addr[i]; i--)
			if((netw->in6.addr[i] & addr->in6.addr[i])
			!= (addr->in6.addr[i] & addr->in6.addr[i]))
				return 0;
		return 1;
	default:
		errno = EAFNOSUPPORT; /* Unknown internet protocol */
		return -1;
	}
}

