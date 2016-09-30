/*******************************************************************************
 *
 *                             Messenger Backend
 *     Copyright (C) 2016 Björn Petersen Software Design and Development
 *                   Contact: r10s@b44t.com, http://b44t.com
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see http://www.gnu.org/licenses/ .
 *
 *******************************************************************************
 *
 * File:    mrlog.c
 * Authors: Björn Petersen
 * Purpose: Error handling, see header for details.
 *
 ******************************************************************************/


#include <stdlib.h>
#include <stdio.h>
#include "mrmailbox.h"
#include "mrlog.h"



static void mr_log(char type, const char* msg)
{
	if( msg == NULL ) {
		return; /* this may happen if eg. sqlite3_mprintf() cannot allocate memory - normally, not. */
	}

	const char* type_str;
	switch( type ) {
		case 'i': type_str = "Information"; break;
		case 'w': type_str = "Warning"; break;
		default:  type_str = "ERROR"; break;
	}

	char* p = sqlite3_mprintf("[%s] %s", type_str, msg);
	if( p ) {
		printf("%s\n", p);
		sqlite3_free(p);
	}
}


void mr_log_info(const char* msg)
{
	mr_log('i', msg);
}



void mr_log_warning(const char* msg)
{
	mr_log('w', msg);
}


void mr_log_error(const char* msg)
{
	mr_log('e', msg);
}



