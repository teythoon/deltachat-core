/*******************************************************************************
 *
 *                              Delta Chat Core
 *                      Copyright (C) 2017 Björn Petersen
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
 ******************************************************************************/


#include "mrmailbox_internal.h"


/**
 * Create an array object in memory.
 *
 * @private @memberof mrarray_t
 *
 * @param mailbox The mailbox object that should be stored in the array object. May be NULL.
 * @param initsize Initial maximal size of the array. If you add more items, the internal data pointer is reallocated.
 *
 * @return New array object of the requested size, the data should be set directly.
 */
mrarray_t* mrarray_new(mrmailbox_t* mailbox, size_t initsize)
{
	mrarray_t* array;

	array = (mrarray_t*) malloc(sizeof(mrarray_t));
	if( array==NULL ) {
		exit(47);
	}

	array->m_mailbox   = mailbox;
	array->m_count     = 0;
	array->m_allocated = initsize < 1? 1 : initsize;
	array->m_array     = malloc(array->m_allocated * sizeof(uintptr_t));
	if( array->m_array==NULL ) {
		exit(48);
	}

	return array;
}


/**
 * Free an array object.
 *
 * @memberof mrarray_t
 *
 * @param array The array object to free, created eg. by mrmailbox_get_chatlist(), mrmailbox_get_known_contacts() and so on.
 *
 * @return None.
 *
 */
void mrarray_unref(mrarray_t* array)
{
	if( array==NULL ) {
		return;
	}

	free(array->m_array);
	free(array);
}


/**
 * Empty an array object. Allocated data is not freed by this function, only the count is set to null.
 *
 * @private @memberof mrarray_t
 *
 * @param array The array object to empty.
 *
 * @return None.
 */
void mrarray_empty(mrarray_t* array)
{
	if( array == NULL ) {
		return;
	}

	array->m_count = 0;
}


/**
 * Add an ID-item to the array.
 * After calling this function the size of the array grows by one.
 * It is okay to add the ID 0, event in this case, the array grows by one.
 *
 * @param array The array to add the item to.
 *
 * @param item The item to add.
 *
 * @return None.
 */
void mrarray_add_id(mrarray_t* array, uint32_t item)
{
	if( array == NULL ) {
		return;
	}

	if( array->m_count == array->m_allocated ) {
		int newsize = (array->m_allocated * 2) + 10;
		if( (array->m_array=realloc(array->m_array, newsize*sizeof(uintptr_t)))==NULL ) {
			exit(49);
		}
		array->m_allocated = newsize;
	}

	array->m_array[array->m_count] = item;
	array->m_count++;
}


/**
 * Find out the number of items in an array.
 *
 * @memberof mrarray_t
 *
 * @param array The array object.
 *
 * @return Returns the number of items in a mrarray_t object. 0 on errors or if the array is empty.
 */
size_t mrarray_get_cnt(mrarray_t* array)
{
	if( array == NULL ) {
		return 0;
	}

	return array->m_count;
}


/**
 * Get the item at the given index as an ID.
 *
 * @memberof mrarray_t
 *
 * @param array The array object.
 * @param index Index of the item to get. Must be between 0 and mrarray_get_cnt()-1.
 *
 * @return Returns the item at the given index. Returns 0 on errors or if the array is empty.
 */
uint32_t mrarray_get_id(mrarray_t* array, size_t index)
{
	if( array == NULL || index < 0 || index >= array->m_count ) {
		return 0;
	}

	return array->m_array[index];
}



/**
 * Check if a given ID is present in an array.
 *
 * @private @memberof mrarray_t
 *
 * @param array The array object to search in.
 * @param needle The ID to search for.
 * @param ret_index If set, this will receive the index. Set to NULL if you're not interested in the index.
 *
 * @return 1=ID is present in array, 0=ID not found.
 */
int mrarray_search_id(mrarray_t* array, uint32_t needle, size_t* ret_index)
{
	if( array == NULL ) {
		return 0;
	}

	uintptr_t* data = array->m_array;
	size_t i, cnt = array->m_count;
	for( i=0; i<cnt; i++ )
	{
		if( data[i] == needle ) {
			if( ret_index ) {
				*ret_index = i;
			}
			return 1;
		}
	}

	return 0;
}
