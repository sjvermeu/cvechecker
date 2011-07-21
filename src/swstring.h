#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Copyright 2010 Sven Vermeulen.
 * Subject to the GNU Public License, version 3.
 */
 
// zero_string - Empty the selected string buffer (fill with 0x00's)
void zero_string(char * buffer, size_t numlen);

// substitute_variable - Substitute variable in string with proper value
char * substitute_variable(const char * buffer, const char * prevar, const char * postvar, const char * varname, const char * value);


// swstrlen - Return the length of the string as an integer
int swstrlen(const char * buffer);
