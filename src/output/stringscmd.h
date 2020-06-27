#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <bsd/string.h>
#include "../cvecheck_common.h"
#include "../swstring.h"

/*
 * Copyright 2010 Sven Vermeulen.
 * Subject to the GNU Public License, version 3.
 */

// strings_extract_version - Method for extracting the version from the file using the strings command
int strings_extract_version(struct workstate * ws, regex_t * preg, regmatch_t * pmatch, struct cpe_data * cpe); 
