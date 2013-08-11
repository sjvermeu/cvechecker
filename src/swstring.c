#include "swstring.h"

/*
 * Copyright 2010 Sven Vermeulen.
 * Subject to the GNU Public License, version 3.
 */
 
/**
 * zero_string - Empty the given string and fill it up with 0x00's.
 *
 * @param buffer Pointer to the string, should be non-NULL.
 * @param numlen Length of the buffer. If 0 or lower, the length of the buffer * is calculated using strlen().
 */
void zero_string(char * buffer, size_t numlen) {
	assert(buffer != NULL);

	if (numlen <= 0) 
		numlen = strlen(buffer);

	memset(buffer, 0x00, numlen);
};

/**
 * swstrlen - Return the length of the string as an integer
 *
 * swstrlen supports stringlength checks on NULL as well - it returns
 * it as 0.
 */
int swstrlen(const char * buffer) {
	if (buffer == NULL)
		return 0;
	else
		return buffer[0] == '\0' ? 0 : strlen(buffer);
};

/**
 * substitute_variable - Substitute variable in string with proper value
 *
 * For safety measures, length of $value needs to be 1023 or less.
 */
char * substitute_variable(const char * buffer, const char * prevar, const char * postvar, const char * varname, const char * value) {
	char * posptr = NULL;
	char * tmpptr = NULL;
	char * newbfr = NULL;
	int found  = 0;

	// Get lengths
	int l_varname = swstrlen(varname);
	int l_buffer  = swstrlen(buffer);
	int l_prevar  = swstrlen(prevar);
	int l_postvar = swstrlen(postvar);
	int l_value   = swstrlen(value);

	// Verify that the lengths aren't unusually large or small...
	if ((l_varname == 0) || (l_varname > l_buffer - l_prevar - l_postvar))
		return NULL;
	if (l_value > 1023)
		return NULL;

	// Allocate room for filled in string

	newbfr = (char *) calloc(sizeof(char), l_buffer - l_prevar - l_postvar - l_varname + l_value + 1);

	if (prevar != NULL) {
		posptr = strstr(buffer, prevar);
		while(posptr != NULL) {
			if (strncmp(posptr + l_prevar, varname, l_varname) == 0) {
				strncpy(newbfr, buffer, l_buffer - swstrlen(posptr));  // First part
				strcat(newbfr, value);                                 // Add value
				if (postvar != NULL) {
					tmpptr = strstr(posptr + l_prevar, postvar);
					strcat(newbfr, tmpptr + l_postvar);
				} else {
					strcat(newbfr, posptr + l_prevar + l_varname);
				};
				found++;
			};
			tmpptr = strstr(posptr + l_prevar, prevar);
			posptr = tmpptr;
		};
	} else {
		posptr = strstr(buffer, varname);
		while(posptr != NULL) {
			strncpy(newbfr, buffer, l_buffer - swstrlen(posptr)); // First part
			strcat(newbfr, value);                                // Add value
			if (postvar != NULL) {
				tmpptr = strstr(posptr + l_varname, postvar);
				strcat(newbfr, tmpptr + l_postvar);
			} else {
				strcat(newbfr, posptr + l_varname);
			};
			found++;
			tmpptr = strstr(posptr + l_varname, varname);
			posptr = tmpptr;
		};
	};
	if (found > 0) {
		return newbfr;
	} else {
		free(newbfr);
		return NULL;
	};
};
