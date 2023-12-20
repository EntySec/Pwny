/*
 * Copyright (c) 2006, 2007 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
#ifndef _LIBPROC_H_
#define _LIBPROC_H_

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <stdint.h>

#include <sys/proc_info.h>

#define SHARED_REGION_SIZE_I386			0x20000000ULL
#define SHARED_REGION_SIZE_X86_64		0x000000009FE00000ULL
#define SHARED_REGION_SIZE_PPC			0x20000000ULL
#define SHARED_REGION_SIZE_PPC64		0x00000000A0000000ULL
#define SHARED_REGION_SIZE_ARM			0x10000000ULL

/*
 * This header file contains private interfaces to obtain process information.  
 * These interfaces are subject to change in future releases.
 */

/*!
	@define PROC_LISTPIDSPATH_PATH_IS_VOLUME
	@discussion This flag indicates that all processes that hold open
		file references on the volume associated with the specified
		path should be returned.
 */
#define PROC_LISTPIDSPATH_PATH_IS_VOLUME	1


/*!
	@define PROC_LISTPIDSPATH_EXCLUDE_EVTONLY
	@discussion This flag indicates that file references that were opened
		with the O_EVTONLY flag should be excluded from the matching
		criteria.
 */
#define PROC_LISTPIDSPATH_EXCLUDE_EVTONLY	2

__BEGIN_DECLS

int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize);

/*!
	@function proc_listpidspath
	@discussion A function which will search through the current
		processes looking for open file references which match
		a specified path or volume.
	@param type types of processes to be searched (see proc_listpids)
	@param typeinfo adjunct information for type
	@param path file or volume path
	@param pathflags flags to control which files should be considered
		during the process search.
	@param buffer a C array of int-sized values to be filled with
		process identifiers that hold an open file reference
		matching the specified path or volume.  Pass NULL to
		obtain the minimum buffer size needed to hold the
		currently active processes.
	@param buffersize the size (in bytes) of the provided buffer.
	@result the number of bytes of data returned in the provided buffer;
		-1 if an error was encountered;
 */
int	proc_listpidspath(uint32_t	type,
			  uint32_t	typeinfo,
			  const char	*path,
			  uint32_t	pathflags,
			  void		*buffer,
			  int		buffersize);

int proc_pidinfo(int pid, int flavor, uint64_t arg,  void *buffer, int buffersize);
int proc_pidfdinfo(int pid, int fd, int flavor, void * buffer, int buffersize); 
int proc_name(int pid, void * buffer, uint32_t buffersize);
int proc_regionfilename(int pid, uint64_t address, void * buffer, uint32_t buffersize);
int proc_kmsgbuf(void * buffer, uint32_t buffersize);
int proc_pidpath(int pid, void * buffer, uint32_t  buffersize);
int proc_libversion(int *major, int * minor);
/* 
 * A process can use the following api to set its own process control 
 * state on resoure starvation. The argument can have one of the PROC_SETPC_XX values
 */
#define PROC_SETPC_NONE		0
#define PROC_SETPC_THROTTLEMEM	1
#define PROC_SETPC_SUSPEND	2
#define PROC_SETPC_TERMINATE	3

int proc_setpcontrol(const int control);
__END_DECLS

#endif /*_LIBPROC_H_ */
