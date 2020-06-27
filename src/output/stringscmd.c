#include "stringscmd.h"

/*
 * Copyright 2010-2020 Sven Vermeulen.
 * Subject to the GNU Public License, version 3.
 */
 
int search_and_substitute_group(regex_t * preg, regmatch_t * pmatch, char * data, struct cpe_data * cpe, int groupid) {
	char buffer[FIELDSIZE], buffer2[FIELDSIZE];
	int numchars = 0;
	int width = 0;

	zero_string(buffer, FIELDSIZE);
	zero_string(buffer2, FIELDSIZE);

	numchars = sprintf(buffer, "\\%d", groupid);

	buffer2[0] = 0x00;

	width = pmatch[groupid].rm_eo - pmatch[groupid].rm_so;

	if (width <= 0) {
		return 1;
	} else if (width > FIELDSIZE-1) {
		return 2;	// Match is larger than FIELDSIZE-1 characters
	};

	if (strstr(cpe->version, buffer) != NULL) {
		memcpy(buffer2, cpe->version, strlen(cpe->version) - strlen(strstr(cpe->version, buffer)));
		strncat(buffer2, data + pmatch[groupid].rm_so, width);
		strncat(buffer2, strstr(cpe->version, buffer) + numchars, strlen(cpe->version) - strlen(strstr(cpe->version, buffer)) + numchars);
		zero_string(cpe->version, FIELDSIZE);
		strlcpy(cpe->version, buffer2, FIELDSIZE);
	};
	if (strstr(cpe->update, buffer) != NULL) {
		memcpy(buffer2, cpe->update, strlen(cpe->update) - strlen(strstr(cpe->update, buffer)));
		strncat(buffer2, data + pmatch[groupid].rm_so, width);
		strncat(buffer2, strstr(cpe->update, buffer) + numchars, strlen(cpe->update) - strlen(strstr(cpe->update, buffer)) + numchars);
		zero_string(cpe->update, FIELDSIZE);
		strlcpy(cpe->update, buffer2, FIELDSIZE);
	};
	if (strstr(cpe->edition, buffer) != NULL) {
		memcpy(buffer2, cpe->edition, strlen(cpe->edition) - strlen(strstr(cpe->edition, buffer)));
		strncat(buffer2, data + pmatch[groupid].rm_so, width);
		strncat(buffer2, strstr(cpe->edition, buffer) + numchars, strlen(cpe->edition) - strlen(strstr(cpe->edition, buffer)) + numchars);
		zero_string(cpe->edition, FIELDSIZE);
		strlcpy(cpe->edition, buffer2, FIELDSIZE);
	};
	if (strstr(cpe->language, buffer) != NULL) {
		memcpy(buffer2, cpe->language, strlen(cpe->language) - strlen(strstr(cpe->language, buffer)));
		strncat(buffer2, data + pmatch[groupid].rm_so, width);
		strncat(buffer2, strstr(cpe->language, buffer) + numchars, strlen(cpe->language) - strlen(strstr(cpe->language, buffer)) + numchars);
		zero_string(cpe->language, FIELDSIZE);
		strlcpy(cpe->language, buffer2, FIELDSIZE);
	};
	if (strstr(cpe->swedition, buffer) != NULL) {
		memcpy(buffer2, cpe->swedition, strlen(cpe->swedition) - strlen(strstr(cpe->swedition, buffer)));
		strncat(buffer2, data + pmatch[groupid].rm_so, width);
		strncat(buffer2, strstr(cpe->swedition, buffer) + numchars, strlen(cpe->swedition) - strlen(strstr(cpe->swedition, buffer)) + numchars);
		zero_string(cpe->swedition, FIELDSIZE);
		strlcpy(cpe->swedition, buffer2, FIELDSIZE);
	};
	if (strstr(cpe->targetsw, buffer) != NULL) {
		memcpy(buffer2, cpe->targetsw, strlen(cpe->targetsw) - strlen(strstr(cpe->targetsw, buffer)));
		strncat(buffer2, data + pmatch[groupid].rm_so, width);
		strncat(buffer2, strstr(cpe->targetsw, buffer) + numchars, strlen(cpe->targetsw) - strlen(strstr(cpe->targetsw, buffer)) + numchars);
		zero_string(cpe->targetsw, FIELDSIZE);
		strlcpy(cpe->targetsw, buffer2, FIELDSIZE);
	};
	if (strstr(cpe->targethw, buffer) != NULL) {
		memcpy(buffer2, cpe->targethw, strlen(cpe->targethw) - strlen(strstr(cpe->targethw, buffer)));
		strncat(buffer2, data + pmatch[groupid].rm_so, width);
		strncat(buffer2, strstr(cpe->targethw, buffer) + numchars, strlen(cpe->targethw) - strlen(strstr(cpe->targethw, buffer)) + numchars);
		zero_string(cpe->targethw, FIELDSIZE);
		strlcpy(cpe->targethw, buffer2, FIELDSIZE);
	};
	if (strstr(cpe->other, buffer) != NULL) {
		memcpy(buffer2, cpe->other, strlen(cpe->other) - strlen(strstr(cpe->other, buffer)));
		strncat(buffer2, data + pmatch[groupid].rm_so, width);
		strncat(buffer2, strstr(cpe->other, buffer) + numchars, strlen(cpe->other) - strlen(strstr(cpe->other, buffer)) + numchars);
		zero_string(cpe->other, FIELDSIZE);
		strlcpy(cpe->other, buffer2, FIELDSIZE);
	};

	return 0;
};

int strings_extract_version(struct workstate * ws, regex_t * preg, regmatch_t * pmatch, struct cpe_data * cpe) {
	const char * stringcmd = NULL;
	char file[FILENAMESIZE];
	char data[FILENAMESIZE];
	FILE * workfile = NULL;
	const config_setting_t * stringcmdcfg = NULL;
	char * buffer;
	int rc;
	int retv;

	zero_string(data, BUFFERSIZE);

	stringcmdcfg = config_lookup(ws->cfg, "stringcmd");
	if (stringcmdcfg == NULL) {
		fprintf(stderr, "Configuration file does not contain stringcmd directive.\n");
		return 1;
	};
	stringcmd    = config_setting_get_string(stringcmdcfg);
	if ((swstrlen(stringcmd) == 0) || (swstrlen(stringcmd) > FILENAMESIZE-1)) {
		fprintf(stderr, "Configuration files 'stringcmd' directive cannot be empty or exceed %d characters\n", FILENAMESIZE-1);
		return 1;
	};

	if (swstrlen(ws->currentdir)+swstrlen(ws->currentfile) > FILENAMESIZE-1) {
		fprintf(stderr, "File path cannot exceed %d characters\n", FILENAMESIZE-1);
		return 1;
	};

	sprintf(file, "%s/%s", ws->currentdir, ws->currentfile);
	buffer = substitute_variable(stringcmd, "@", "@", "file", file);

	retv = 1;

	workfile = popen(buffer, "r");
	while (fgets(data, FILENAMESIZE, workfile) != 0) {
		if (data[FILENAMESIZE-1] != 0x00) 
			data[FILENAMESIZE-1] = 0x00;
		if (data[swstrlen(data)-1] == '\n')
			data[swstrlen(data)-1] = 0x00;
		rc = regexec(preg, data, 16, pmatch, 0);
		if (!rc) {
			retv = 0;
			// Found a match, extracting version (but first, print it out)
			for (rc = preg->re_nsub; rc > 0; rc--) {
				retv += search_and_substitute_group(preg, pmatch, data, cpe, rc);
			};
			break;
		};
		zero_string(data, FILENAMESIZE);
	}
	pclose(workfile);
	free(buffer);

	return retv;
};

