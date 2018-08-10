#include "cvecheck.h"
/*
 * Copyright 2010-2017 Sven Vermeulen.
 * Subject to the GNU Public License, version 3.
 */
 
/***********************************************************************************************
 * Helper functions for the CPE and CVE structures
 ***********************************************************************************************/

/**
 * Convert the selected cpe_data structure to a string
 */
void cpe_to_string(char * buffer, int buffsize, struct cpe_data cpe) {
	int rc      = 0;

	zero_string(buffer, buffsize);

	rc = snprintf(buffer, buffsize, "cpe:/%c:%s:%s:%s:%s:%s:%s", cpe.part, cpe.vendor, cpe.product, cpe.version, cpe.update, cpe.edition, cpe.language);
	if ((rc == 0) || (rc == buffsize)) {
		/* 
		 * No bytes written, or buffer full -> doesn't seem right.  Return null
		 */
		zero_string(buffer, buffsize);
	};
};

/**
 * Convert the selected string to a cpe_data structure
 */
void string_to_cpe(struct cpe_data * cpe, char * buffer) {
	char * cpos = NULL;
	char * nextpos = NULL;

	int fieldwidth = 0;

	cpos = strstr(buffer, "cpe:/");
	if (cpos == NULL)
		return;
	cpos += 5;
	nextpos = strchr(cpos, ':');

	if (nextpos == 0)
		return;

	cpe->part = cpos[0];

	// Iterations start here ;-)
	cpos = nextpos+1;
	nextpos = strchr(cpos, ':');

	if (nextpos == 0)
		return;

	fieldwidth = swstrlen(cpos) - swstrlen(nextpos);
	// The length of the fields is always at most FIELDSIZE.
	if (fieldwidth >= FIELDSIZE)
		fieldwidth = FIELDSIZE - 1;
	strncpy(cpe->vendor, cpos, fieldwidth);
	cpe->vendor[fieldwidth] = '\0';

	cpos = nextpos+1;
	nextpos = strchr(cpos, ':');
	if (nextpos != NULL) {
		fieldwidth = swstrlen(cpos) - swstrlen(nextpos);
		if (fieldwidth >= FIELDSIZE)
			fieldwidth = FIELDSIZE - 1;
		strncpy(cpe->product, cpos, fieldwidth);
		cpe->product[fieldwidth] = '\0';
	} else {
		fieldwidth = swstrlen(cpos);
		if (fieldwidth >= FIELDSIZE)
			fieldwidth = FIELDSIZE - 1;
		strncpy(cpe->product, cpos, fieldwidth);
		cpe->product[fieldwidth] = '\0';
		cpe->version[0] = '\0';
		cpe->update[0] = '\0';
		cpe->edition[0] = '\0';
		cpe->language[0] = '\0';

		return;

	}

	cpos = nextpos+1;
	nextpos = strchr(cpos, ':');
	if (nextpos != NULL) {
		fieldwidth = swstrlen(cpos) - swstrlen(nextpos);
		if (fieldwidth >= FIELDSIZE)
			fieldwidth = FIELDSIZE - 1;
		strncpy(cpe->version, cpos, fieldwidth);
		cpe->version[fieldwidth] = '\0';
	} else {
		fieldwidth = swstrlen(cpos);
		if (fieldwidth >= FIELDSIZE)
			fieldwidth = FIELDSIZE - 1;
		strncpy(cpe->version, cpos, fieldwidth);
		cpe->version[fieldwidth] = '\0';
		cpe->update[0] = '\0';
		cpe->edition[0] = '\0';
		cpe->language[0] = '\0';

		return;
	}

	cpos = nextpos+1;
	nextpos = strchr(cpos, ':');
	if (nextpos != NULL) {
		fieldwidth = swstrlen(cpos) - swstrlen(nextpos);
		if (fieldwidth >= FIELDSIZE)
			fieldwidth = FIELDSIZE - 1;
		strncpy(cpe->update, cpos, fieldwidth);
		cpe->update[fieldwidth] = '\0';
	} else {
		fieldwidth = swstrlen(cpos);
		if (fieldwidth >= FIELDSIZE)
			fieldwidth = FIELDSIZE - 1;
		strncpy(cpe->update, cpos, fieldwidth);
		cpe->update[fieldwidth] = '\0';
		cpe->edition[0] = '\0';
		cpe->language[0] = '\0';

		return;
	}

	cpos = nextpos+1;
	nextpos = strchr(cpos, ':');
	if (nextpos != NULL) {
		fieldwidth = swstrlen(cpos) - swstrlen(nextpos);
		if (fieldwidth >= FIELDSIZE)
			fieldwidth = FIELDSIZE - 1;
		strncpy(cpe->edition, cpos, fieldwidth);
		cpe->edition[fieldwidth] = '\0';
	} else {
		fieldwidth = swstrlen(cpos);
		if (fieldwidth >= FIELDSIZE)
			fieldwidth = FIELDSIZE - 1;
		strncpy(cpe->edition, cpos, fieldwidth);
		cpe->edition[fieldwidth] = '\0';
		cpe->language[0] = '\0';
		
		return;
	}

	cpos = nextpos+1;
	nextpos = strchr(cpos, ':');
	if (nextpos != NULL) {
		fieldwidth = swstrlen(cpos) - swstrlen(nextpos);
		if (fieldwidth >= FIELDSIZE)
			fieldwidth = FIELDSIZE - 1;
		strncpy(cpe->language, cpos, fieldwidth);
		cpe->language[fieldwidth] = '\0';
	} else {
		fieldwidth = swstrlen(cpos);
		if (fieldwidth >= FIELDSIZE)
			fieldwidth = FIELDSIZE - 1;
		strncpy(cpe->language, cpos, fieldwidth);
		cpe->language[fieldwidth] = '\0';
		cpe->language[0] = '\0';
		
		return;
	}
};

int copy_cpe(struct cpe_data * target, struct cpe_data * source) {
  struct cpe_data * ptr;

  target->part = source->part;
  ptr = (struct cpe_data *) strcpy(target->vendor, source->vendor);
  if ((struct cpe_data *) ptr != (struct cpe_data *) target->vendor)
    return 1;
  ptr = (struct cpe_data *) strcpy(target->product, source->product);
  if ((struct cpe_data *) ptr != (struct cpe_data *) target->product)
    return 2;
  ptr = (struct cpe_data *) strcpy(target->version, source->version);
  if ((struct cpe_data *) ptr != (struct cpe_data *) target->version)
    return 3;
  ptr = (struct cpe_data *) strcpy(target->update, "");
  if ((struct cpe_data *) ptr != (struct cpe_data *) target->update)
    return 4;
  ptr = (struct cpe_data *) strcpy(target->edition, "");
  if ((struct cpe_data *) ptr != (struct cpe_data *) target->edition)
    return 5;
  ptr = (struct cpe_data *) strcpy(target->language, "");
  if ((struct cpe_data *) ptr != (struct cpe_data *) target->language)
    return 6;
  return 0;
};

/**
 * Gather the year and sequence identifiers from the CVE string
 */
int cve_to_vars(int * year, int * sequence, char * cveId) {
	char buffer[16];
	char * start = NULL;
	char * end   = NULL;
	size_t s_start = 0;
	size_t s_end   = 0;

	start = strchr(cveId, '-')+1;
	end = strrchr(cveId, '-');

	if ((start == NULL) || (end == NULL)) {
		/*
		 * Fishy
		 */
		return 1;
	};

	s_start = strlen(start);
	s_end   = strlen(end);

	strncpy(buffer, start, s_start-s_end);
	buffer[s_start-s_end] = '\0';

	*year = atoi(buffer);

	strncpy(buffer, end+1, strlen(end+1));
	buffer[strlen(end+1)] = '\0';

	*sequence = atoi(buffer);

	return 0;
};

/**
 * Extract a version number from a version string
 *
 * Method: each time a set of numbers is received, the resulting number is
 * an integer field (part of the version). If non-numbers are found, they
 * are usually seen as a field separator.
 *
 * However, if the first character of a non-number field is '.', '-' or '_' 
 * and the next character is part of a-z or A-Z, then this next character is 
 * seen as a /negative/ value. If the first character of a non-number field is 
 * part of a-z or A-Z, then it is seen as a positive number.
 *
 * Example:
 *   OpenSSL 0.9.8    -> 0.9.8.0     (is less/lower than)
 *   OpenSSL 0.9.8b   -> 0.9.8.226   (is less/lower than)
 *   OpenSSL 0.9.8c   -> 0.9.8.227
 *
 *   InTouch 0.5.1_alpha   -> 0.5.1.-31 (is less/lower than)
 *   InTouch 0.5.1         -> 0.5.1.0
 */
int get_version_field(const char * version, int fieldnum) {
  int charctr = 0;
  int maxchar = swstrlen(version);
  while (fieldnum != -1) {
    while (((version[charctr] > '9') || (version[charctr] < '0')) && (charctr < maxchar))
      charctr++;
    // Now at start of a number
    if (fieldnum == 0) {
      // Return field
      return atoi(version+charctr);
    } else {
      int usepositive = 1;
      // Not this field. Jump to next
      while (((version[charctr] >= '0') && (version[charctr] <= '9')) && (charctr < maxchar))
        charctr++;
      fieldnum--;  
      // If next character is ., - or _, skip it first
      if ((version[charctr] == '.') || (version[charctr] == '-') || (version[charctr] == '_')) {
        usepositive = -1;
        charctr++;
      };
      // If next character is a-zA-Z, treat it as a (negative) number
      if (((version[charctr] >= 'A') && (version[charctr] <= 'Z')) ||
          ((version[charctr] >= 'a') && (version[charctr] <= 'z'))) {
        if (fieldnum == 0) {
          return (usepositive * 128) + (unsigned int) version[charctr];
	} else {
	  fieldnum--;
	}
      }
    };
  };
  return 0;
};

/***********************************************************************************************
 * Wrapper functions
 *
 * These functions will provide basic functionality for the cvechecker tool, but
 * will also call the specific implementation functions of the target database
 * (using the *_dbimpl_* functions).
 ***********************************************************************************************/


/**
 * Reads configuration from a configuration file.
 *
 * If the file can not be statted return -1
 */
int initialize_configuration(struct workstate * ws, char * configfile) {
	struct stat filestat;
	if (stat(configfile, &filestat) > -1) {
		if (config_read_file(ws->cfg, configfile) == CONFIG_FALSE) {
			fprintf(stderr, "Could not process configuration file \"%s\" - %s at line %d", configfile, config_error_text(ws->cfg), config_error_line(ws->cfg));
			exit(EXIT_FAILURE);
		} else {
			return 0;
		};
	} else {
		return -1;
	};
};


/**
 * Initialize configuration file
 *
 * Locate the configuration file, first by reading the home location and, if
 * that file doesn't exist, use the /etc location.
 */
int initialize_configfile(struct workstate * ws) {
	char * ENV_VARIABLE = "CVECHECKER_CONFFILE";
	// Configuration file
	char * configfile;
	char * homeloc;


	ws->cfg = (config_t *) calloc(sizeof(config_t), 1);
	if (ws->cfg == NULL) {
		fprintf(stderr, "Could not reserve system memory for allocation\n");
		exit(EXIT_FAILURE);
	};
	config_init(ws->cfg);


	//Check for location of configuration file in environment variable
	configfile = getenv(ENV_VARIABLE);
	if (configfile != NULL) {
		if (initialize_configuration(ws, configfile) == -1) {
			fprintf(stderr, "Configuration file %s specified via environment variable \"%s\", but does not exist.\n", configfile, ENV_VARIABLE);
			exit(EXIT_FAILURE);
		} else {
			return 0;
		}
	};


	configfile = (char *) calloc(sizeof(char), FILENAMESIZE);
	if (configfile == NULL) {
		fprintf(stderr, "Could not reserve system memory for allocation\n");
		exit(EXIT_FAILURE);
	}


	//Check for configuration file in home directory
	homeloc = getenv("HOME");
	if (homeloc != NULL) {
		strncpy(configfile, homeloc, FILENAMESIZE-16);
		strcat(configfile, "/.cvechecker.rc");
		if(initialize_configuration(ws, configfile) == 0) {
			free(configfile);
			return 0;
		};
	};


	//Check for configuration file in /usr/local/etc
	zero_string(configfile, FILENAMESIZE);
	strcpy(configfile, "/usr/local/etc/cvechecker.conf");
	if (initialize_configuration(ws, configfile) == 0) {
		free(configfile);
		return 0;
	};


	//Check for configuration file in /etc
	zero_string(configfile, FILENAMESIZE);
	strcpy(configfile, "/etc/cvechecker.conf");
	if (initialize_configuration(ws, configfile) == 0) {
		free(configfile);
		return 0;
	};

	fprintf(stderr, "Could not locate a configuration file. Environment variable \"%s\" was not set. No \".cvechecker.rc\" file was located in the users home directory and no \"cvechecker.conf\" file was located in either of the \"/usr/local/etc\" or \"/etc\" directories.", ENV_VARIABLE);
	exit(EXIT_FAILURE);

};

/**
 * Initialize the database target
 *
 * cvechecker aims to support multiple target databases, so we need to read
 * in which database (type) the user wants to use and take the necessary
 * steps.
 */
int initialize_dbtarget(struct workstate * ws) {
  const config_setting_t * dbtype;
  int rc;

  /*
   * Load the set of databases
   */
  dbtype = config_lookup(ws->cfg, "dbtype");
  if (dbtype == NULL) {
    fprintf(stderr, "Configuration file does not contain dbtype directive.\n");
    return 1;
  };
  rc = strlen(config_setting_get_string(dbtype));
  if (rc > 32) {
    fprintf(stderr, "Configuration files 'dbtype' directive cannot exceed 32 characters\n");
    return 1;
  };

  if ((strcmp(config_setting_get_string(dbtype), "sqlite") == 0) && (sqlite_dbimpl_supported() == 1)){
    ws->dbtype = sqlite;
  } else if ((strcmp(config_setting_get_string(dbtype), "sqlite3") == 0) && (sqlite_dbimpl_supported() == 1)) {
    ws->dbtype = sqlite;
  } else if ((strcmp(config_setting_get_string(dbtype), "mysql") == 0) && (mysql_dbimpl_supported() == 1)) {
    ws->dbtype = mysql;
  } else {
    fprintf(stderr, "Database type \"%s\" is not supported.\n", config_setting_get_string(dbtype));
    return 1;
  };

  return 0;
};

/**
 * Initialize the workstate variable.
 *
 * The workstate variable is the main structure used throughout the application.
 * It provides access to the databases (and other technologies) used by the
 * application.
 */
int initialize_workstate(struct workstate * ws, struct arguments * arg) {
	int rc;
	const config_setting_t * confkey;

	rc = initialize_configfile(ws);
	rc += initialize_dbtarget(ws);
	ws->arg = arg;
	ws->versionListCleared = 0;

	// Set the hostname, can be used by database implementations
	ws->hostname = (char *) calloc(FIELDSIZE, sizeof(char));
	gethostname(ws->hostname, FIELDSIZE);

	// Set the userdefined key, can be used by database implementations
	ws->userdefkey = (char *) calloc(FIELDSIZE, sizeof(char));
	confkey = config_lookup(ws->cfg, "userkey");
	if (confkey == NULL) {
		// No userkey defined - that's okay, not mandatory. We default
		// to hostname then
		strncpy(ws->userdefkey, ws->hostname, FIELDSIZE);
	} else {
		rc = strlen(config_setting_get_string(confkey));
		if (rc > FIELDSIZE-1) {
			fprintf(stderr, "Configuration file directive \'userkey\' cannot exceed %d characters.\n", FIELDSIZE-1);
			fprintf(stderr, "Defaulting to hostname as user key.\n");
			strncpy(ws->userdefkey, ws->hostname, FIELDSIZE);
		} else {
			strncpy(ws->userdefkey, config_setting_get_string(confkey), FIELDSIZE);
		}
	};
	

	if (ws->dbtype == sqlite) {
		// Call argument check (this is not possible before as we did not
		// know what the dbtype was at that time.
		sqlite_dbimpl_initialize_arguments(arg);

		// Call the specific database implementation
		rc += sqlite_dbimpl_initialize_workstate(ws);
	} else if (ws->dbtype == mysql) {
		rc += mysql_dbimpl_initialize_workstate(ws);
	}

	return rc;
};


/**
 * Initialize the databases
 */
void initialize_databases(struct workstate * ws) {
	if (ws->dbtype == sqlite)
		sqlite_dbimpl_initialize_databases(ws);
	else if (ws->dbtype == mysql)
		mysql_dbimpl_initialize_databases(ws);
};

/**
 * Load the databases into the workstate
 *
 * The function is responsible for loading in the database(s) needed by the
 * application into the workstate variable.
 */
int load_databases(struct workstate * ws) {
	if (ws->dbtype == sqlite)
		return sqlite_dbimpl_load_databases(ws);
	else if (ws->dbtype == mysql) {
		return mysql_dbimpl_load_databases(ws);
	}
	
	return 1;
};


/**
 * Open the provided version data file
 */
int init_versiondata(struct workstate * ws) {
	struct arguments * arg = ws->arg;
	ws->datafile = fopen(arg->datafile, "r");
	if (ws->datafile == NULL) {
		fprintf(stderr, "Could not open file %s for reading: ", arg->datafile);
		perror(arg->datafile);
		return 1;
	};

	return 0;
};

/**
 * Open the provided system file (with CPE listing).
 */
int init_watchlist(struct workstate * ws) {
	struct arguments * arg = ws->arg;
	ws->watchlist = fopen(arg->watchlist, "r");
	if (ws->watchlist == NULL) {
		fprintf(stderr, "Could not open file %s for reading: ", arg->watchlist);
		perror(arg->watchlist);
		return 1;
	};

	return 0;
};

/**
 * Open the provided system file (with paths to binary files).
 */
int init_binlist(struct workstate * ws) {
	struct arguments * arg = ws->arg;
	if (strcmp(arg->binlist, "-")) {
		ws->binlist = fopen(arg->binlist, "r");
		if (ws->binlist == NULL) {
			fprintf(stderr, "Could not open file %s for reading: ", arg->binlist);
			perror(arg->binlist);
			return 1;
		};
	} else {
		ws->binlist = stdin;
	}

	return 0;
};

/**
 * Check the installed software list against the current CVE listing.
 */
void verify_installed_versus_cve(struct workstate * ws) {
	if (ws->arg->docsvoutput)
		fprintf(stdout, "Outputversion,File,CPE,CVE,CVSS,Matchtype,Hostname,Userkey\n");
	if (ws->dbtype == sqlite)
		sqlite_dbimpl_verify_installed_versus_cve(ws);
	else if (ws->dbtype == mysql) 
		mysql_dbimpl_verify_installed_versus_cve(ws);
}

/**
 * Match the selected file to see if it is a candidate (known in the database)
 *
 * If the selected file is a known candidate (the master database contains at
 * least one entry on how to grab the version of this file), it is processed.
 */
int match_binary(char * file, struct workstate * ws) {
	char * basedir;
	char * filename;
	char * slashpos;
	int fieldwidth = 0;

	basedir = (char *) calloc(sizeof(char), FILENAMESIZE);
	filename = (char *) calloc(sizeof(char), FILENAMESIZE);

	if ((basedir == NULL) || (filename == NULL)) {
		fprintf(stderr, "Failed to allocate memory\n");
		exit(EXIT_FAILURE);
	};

	slashpos = strrchr(file, '/');
	if (slashpos == NULL) {
		fprintf(stderr, "Failed to find basedir for file %s\n", file);
		free(basedir);
		free(filename);
		return 2;
	}

	fieldwidth = swstrlen(file) - swstrlen(slashpos);
	strncpy(basedir, file, fieldwidth);
	basedir[fieldwidth] = '\0';
	strncpy(filename, slashpos+1, strlen(slashpos)-1);
	filename[swstrlen(slashpos)-1] = '\0';
	ws->currentdir=basedir;
	ws->currentfile=filename;

	ws->rc=0;	// Re-init state

	if (ws->dbtype == sqlite)
		fieldwidth = sqlite_dbimpl_process_binary(ws);
	else if (ws->dbtype == mysql) {
		fieldwidth = mysql_dbimpl_process_binary(ws);
	}

	free(ws->currentdir);
	free(ws->currentfile);

	return fieldwidth;
};

/**
 * Show the potential vulnerability matches
 */
void show_potential_vulnerabilities(struct workstate * ws, int cveyear, int cvenum, int cvssScore, const char * filename, struct cpe_data cpe, int versiononly) {
	char buffer[BUFFERSIZE];
	struct arguments * arg = ws->arg;
	int matchtype = -1;

	if (versiononly == 1)
	  matchtype = 0;
	else if (versiononly == 0)
	  matchtype = 1;
	else 
	  matchtype = versiononly;
		
	zero_string(buffer, BUFFERSIZE);
	cpe_to_string(buffer, BUFFERSIZE, cpe);
	if (arg->docsvoutput) {
		fprintf(stdout, "3,%s,%s,CVE-%.4d-%.4d,%.1f,%d,%s,%s\n", filename, buffer, cveyear, cvenum, (cvssScore * 1.0 / 10), matchtype, ws->hostname, ws->userdefkey);
	} else {
		if (matchtype == 0) {
			fprintf(stdout, "File \"%s\" (CPE = %s) on host %s (key %s)\n  Potential vulnerability found (CVE-%.4d-%.4d)\n  CVSS Score is %.1f\n  Vulnerability match is version only\n", filename, buffer, ws->hostname, ws->userdefkey, cveyear, cvenum, (cvssScore * 1.0 / 10));
		} else if (matchtype == 1) {
			fprintf(stdout, "File \"%s\" (CPE = %s) on host %s (key %s)\n  Potential vulnerability found (CVE-%.4d-%.4d)\n  CVSS Score is %.1f\n  Full vulnerability match (incl. edition/language)\n", filename, buffer, ws->hostname, ws->userdefkey, cveyear, cvenum, (cvssScore * 1.0/ 10));
		} else if (matchtype == 2) {
			fprintf(stdout, "File \"%s\" (CPE = %s) on host %s (key %s)\n  Potential vulnerability found (CVE-%.4d-%.4d)\n  CVSS Score is %.1f\n  Match with potential higher version\n", filename, buffer, ws->hostname, ws->userdefkey, cveyear, cvenum, (cvssScore * 1.0 / 10));
		} else {
			fprintf(stdout, "File \"%s\" (CPE = %s) on host %s (key %s)\n  Potential vulnerability found (CVE-%.4d-%.4d)\n  CVSS Score is %.1f\n  UNIDENTIFIED MATCH RULE\n", filename, buffer, ws->hostname, ws->userdefkey, cveyear, cvenum, (cvssScore * 1.0 / 10));
		};
	};
};

/**
 * Clear the result list
 */
void clear_resultlist(struct workstate * ws) {
	int numresults = ws->numresults;
	int i = 0;

	for (i = 0; i < numresults; i++) {
		free(ws->resultlist[i]);
	};

	ws->numresults = 0;
};

/**
 * Show the installed software
 */
void show_installed_software(struct workstate * ws, const char * vendor, const char * product, const char * version, const char * update, const char * edition, const char * language, int numfiles, const char ** files) {
	struct arguments * arg = ws->arg;
	int filecounter = numfiles;

	if (arg->docsvoutput) {
		fprintf(stdout, "2,%s,%s,%s,%s,%s,%s,%s,%s,", vendor, product, version, update, edition, language, ws->hostname, ws->userdefkey);
		while (filecounter > 0) {
			fprintf(stdout, "%s ", files[--filecounter]);
		};
		fprintf(stdout, "\n");
	} else {
		fprintf(stdout, "Detected vendor=\"%s\", product=\"%s\", version=\"%s\", update=\"%s\", edition=\"%s\", language=\"%s\" on host=\"%s\", userkey=\"%s\"\n", vendor, product, version, update, edition, language, ws->hostname, ws->userdefkey);
		if (filecounter > 0) {
			fprintf(stdout, "Files that contributed to this detection:\n");
			while (filecounter > 0) {
				fprintf(stdout, "  - %s\n", files[--filecounter]);
			};
			fprintf(stdout, "\n");
		};
	};
};

/**
 * Process the version gathering data.
 */
int process_versiondata(char * line, struct workstate * ws) {
	struct versiongather_data vg;
	struct cpe_data cpe;
	char * ptr;
	char * ctrptr;
	char buffer[BUFFERSIZE];
	int startpos = 1;
	int temppos  = 2;
	int ctrpos   = 3;

	ptr = strchr(line+startpos, line[0]);
	if (ptr == NULL) {
		fprintf(stderr, "Error in first field (filepart), could not find field delimiter\n");
		return 1;
	};
	temppos = swstrlen(line+startpos)-swstrlen(ptr);
	if (temppos == 0) {
		fprintf(stderr, "Error in first field (filepart), field cannot be empty\n");
		return 2;
	};
	if (temppos >= FILENAMESIZE) {
		fprintf(stderr, "Error in first field (filepart), field cannot be larger than %u bytes\n", FILENAMESIZE-1);
		return 3;
	};
	strncpy(vg.filepart, line+startpos, temppos);
	vg.filepart[temppos] = '\0';
	startpos += temppos+1;

	ptr = strchr(line+startpos, line[0]);
	if (ptr == NULL) {
		fprintf(stderr, "Error in second field (gathertype), could not find field delimiter\n");
		return 1;
	};
	temppos = swstrlen(line+startpos)-swstrlen(ptr);
	if (temppos == 0) {
		fprintf(stderr, "Error in second field (gathertype), field cannot be empty\n");
		return 2;
	};
	if (temppos != 1) {
		fprintf(stderr, "Error in second field (gathertype), field should be one character long\n");
		return 3;
	};
	strncpy(buffer, line+startpos, temppos);
	buffer[temppos] = '\0';
	vg.gathertype = atoi(buffer);
	startpos += temppos+1;

	ptr = strchr(line+startpos, line[0]);
	if (ptr == NULL) {
		fprintf(stderr, "Error in third field (filematch), could not find field delimiter\n");
		return 1;
	};
	temppos = swstrlen(line+startpos)-swstrlen(ptr);
	if (temppos == 0) {
		fprintf(stderr, "Error in third field (filematch), field cannot be empty\n");
		return 2;
	};
	if (temppos >= FILENAMESIZE) {
		fprintf(stderr, "Error in third field (filematch), field cannot be larger than %u characters\n", FILENAMESIZE-1);
		return 3;
	};
	strncpy(vg.filematch, line+startpos, temppos);
	vg.filematch[temppos] = '\0';
	startpos += temppos+1;

	ptr = strchr(line+startpos, line[0]);
	if (ptr == NULL) {
		fprintf(stderr, "Error in fourth field (contentmatch), could not find field delimiter\n");
		return 1;
	};
	temppos = swstrlen(line+startpos)-swstrlen(ptr);
	if (temppos == 0) {
		fprintf(stderr, "Error in fourth field (contentmatch), field cannot be empty\n");
		return 2;
	};
	if (temppos >= LARGEFIELDSIZE) {
		fprintf(stderr, "Error in fourth field (contentmatch), field cannot be larger than %u characters\n", LARGEFIELDSIZE-1);
		return 3;
	};
	ctrpos = startpos;
	while ((ctrpos <= startpos+temppos) && (ctrpos >= startpos)) {
          ctrptr = strchr(line+ctrpos, '"');
	  if ((ctrptr != NULL) && (ctrptr <= line+temppos)) {
	    ctrpos = swstrlen(line+startpos)-swstrlen(ctrptr);
            if (line[ctrpos-1] != '\\') {
              fprintf(stderr, "Error in fourth field (contentmatch), field cannot contain unquoted \" characters\n");
	      return 4;
	    };
	  } else {
	    ctrpos = 0;
	  };
	  ctrpos++;
	};
	strncpy(vg.versionexpression, line+startpos, temppos);
	vg.versionexpression[temppos] = '\0';
	startpos += temppos+1;

	ptr = strchr(line+startpos, line[0]);
	if (ptr == NULL) {
		fprintf(stderr, "Error in fifth field (cpe part), could not find field delimiter\n");
		return 1;
	};
	temppos = swstrlen(line+startpos)-swstrlen(ptr);
	if (temppos == 0) {
		fprintf(stderr, "Error in fifth field (cpe part), field cannot be empty\n");
		return 2;
	};
	if ((line[startpos] != 'a') && (line[startpos] != 'h') && (line[startpos] != 'o')) {
		fprintf(stderr, "Error in fifth field (cpe part), field should be one of (a,h,o)\n");
		return 3;
	};
	cpe.part = line[startpos];
	startpos += temppos+1;

	ptr = strchr(line+startpos, line[0]);
	if (ptr == NULL) {
		fprintf(stderr, "Error in sixth field (cpe vendor), could not find field delimiter\n");
		return 1;
	};
	temppos = swstrlen(line+startpos)-swstrlen(ptr);
	if (temppos == 0) {
		fprintf(stderr, "Error in sixth field (cpe vendor), field cannot be empty\n");
		return 2;
	};
	if (temppos >= FIELDSIZE) {
		fprintf(stderr, "Error in sixth field (cpe vendor), field cannot be larger than %d characters\n", FIELDSIZE-1);
		return 3;
	};
	strncpy(cpe.vendor, line+startpos, temppos);
	cpe.vendor[temppos] = '\0';
	startpos += temppos+1;

	ptr = strchr(line+startpos, line[0]);
	if (ptr == NULL) {
		fprintf(stderr, "Error in seventh field (cpe product), could not find field delimiter\n");
		return 1;
	};
	temppos = swstrlen(line+startpos)-swstrlen(ptr);
	if (temppos == 0) {
		fprintf(stderr, "Error in seventh field (cpe product), field cannot be empty\n");
		return 2;
	};
	if (temppos >= FIELDSIZE) {
		fprintf(stderr, "Error in seventh field (cpe product), field cannot be larger than %d characters\n", FIELDSIZE-1);
		return 3;
	};
	strncpy(cpe.product, line+startpos, temppos);
	cpe.product[temppos] = '\0';
	startpos += temppos+1;

	ptr = strchr(line+startpos, line[0]);
	if (ptr == NULL) {
		fprintf(stderr, "Error in eighth field (cpe version), could not find field delimiter\n");
		return 1;
	};
	temppos = swstrlen(line+startpos)-swstrlen(ptr);
	if (temppos == 0) {
		fprintf(stderr, "Error in eighth field (cpe version), field cannot be empty\n");
		return 2;
	};
	if (temppos >= FIELDSIZE) {
		fprintf(stderr, "Error in eighth field (cpe version), field cannot be larger than %d characters\n", FIELDSIZE-1);
		return 3;
	};
	strncpy(cpe.version, line+startpos, temppos);
	cpe.version[temppos] = '\0';
	startpos += temppos+1;

	ptr = strchr(line+startpos, line[0]);
	if (ptr == NULL) {
		fprintf(stderr, "Error in ninth field (cpe update), could not find field delimiter\n");
		return 1;
	};
	temppos = swstrlen(line+startpos)-swstrlen(ptr);
	if (temppos >= 64) {
		fprintf(stderr, "Error in ninth field (cpe update), field cannot be larger than 63 characters\n");
		return 3;
	};
	strncpy(cpe.update, line+startpos, temppos);
	cpe.update[temppos] = '\0';
	startpos += temppos+1;

	ptr = strchr(line+startpos, line[0]);
	if (ptr == NULL) {
		fprintf(stderr, "Error in tenth field (cpe edition), could not find field delimiter\n");
		return 1;
	};
	temppos = swstrlen(line+startpos)-swstrlen(ptr);
	if (temppos >= FIELDSIZE) {
		fprintf(stderr, "Error in tenth field (cpe edition), field cannot be larger than %d characters\n", FIELDSIZE-1);
		return 3;
	};
	strncpy(cpe.edition, line+startpos, temppos);
	cpe.edition[temppos] = '\0';
	startpos += temppos+1;

	ptr = strchr(line+startpos, line[0]);
	if (ptr == NULL) {
		cpe.language[0] = '\0';
	} else {
		temppos = swstrlen(line+startpos)-swstrlen(ptr);
		if (temppos >= 64) {
			fprintf(stderr, "Error in eleventh field (cpe language), field cannot be larger than 63 characters\n");
			return 3;
		};
		strncpy(cpe.language, line+startpos, temppos);
		cpe.language[temppos] = '\0';
		if (cpe.language[temppos-1] == 10) // newline, drop it
			cpe.language[temppos-1] = '\0';
	}

	if (ws->dbtype == sqlite)
		return sqlite_dbimpl_add_versiongather(ws, vg, cpe);
	else if (ws->dbtype == mysql)
		return mysql_dbimpl_add_versiongather(ws, vg, cpe);
	else
		return 1;
};

/**
 * Delete the given CPE from the database
 */
int delete_cpe(char * line, struct workstate * ws) {
	struct cpe_data cpe;
	char buffer[BUFFERSIZE];

	char * cdir = (char *) calloc(13, sizeof(char));
	char * clin = (char *) calloc(512, sizeof(char));

	string_to_cpe(&cpe, line);
	cpe_to_string(buffer, BUFFERSIZE, cpe);

	if (strcmp(buffer, line) != 0) {
		return 1;
	};

	// Use __provided__ as tag to show that the file is not detected on the
	// system, but provided by the user through the watchlist.
	ws->currentdir = cdir;
	strcpy(ws->currentdir, "__provided__");

	ws->currentfile = clin;
	strcpy(ws->currentfile, line);

	ws->rc=0;

	if (ws->dbtype == sqlite)
		sqlite_dbimpl_delete_binary(ws);
	else if (ws->dbtype == mysql)
		mysql_dbimpl_delete_binary(ws);

	return 0;
};


/**
 * Delete the given binary file from the database
 */
int delete_binfile(char * line, struct workstate * ws) {
	char * basedir;
	char * filename;
	char * slashpos;
	int fieldwidth = 0;

	basedir = (char *) calloc(sizeof(char), FILENAMESIZE);
	filename = (char *) calloc(sizeof(char), FILENAMESIZE);

	if ((basedir == NULL) || (filename == NULL)) {
		fprintf(stderr, "Failed to allocate memory\n");
		return 1;
	};

	slashpos = strrchr(line, '/');
	if (slashpos == NULL) {
		fprintf(stderr, "Failed to find basedir for file %s\n", line);
		free(basedir);
		free(filename);
		return 2;
	}

	fieldwidth = swstrlen(line) - swstrlen(slashpos);
	strncpy(basedir, line, fieldwidth);
	basedir[fieldwidth] = '\0';
	strncpy(filename, slashpos+1, strlen(slashpos)-1);
	filename[swstrlen(slashpos)-1] = '\0';
	ws->currentdir=basedir;
	ws->currentfile=filename;

	ws->rc=0;	// Re-init state

	if (ws->dbtype == sqlite)
		sqlite_dbimpl_delete_binary(ws);
	else if (ws->dbtype == mysql)
		mysql_dbimpl_delete_binary(ws);

	free(basedir);
	free(filename);

	return 0;
};

/**
 * Add the CPE to the database
 */
int add_cpe(char * line, struct workstate * ws) {
	struct cpe_data cpe;
	char buffer[FIELDSIZE*6+7];

	char * cdir = (char *) calloc(13, sizeof(char));
	char * clin = (char *) calloc(BUFFERSIZE*6+7, sizeof(char));

	if ((strlen(line) == 0) || (line[0] == '#'))
	{
	  free(cdir);
	  free(clin);
	  return 0;
	}

	string_to_cpe(&cpe, line);
	cpe_to_string(buffer, BUFFERSIZE, cpe);

	if (strcmp(buffer, line) != 0) {
		return 1;
	};

	// Use __provided__ as tag to show that the file is not detected on the
	// system, but provided by the user through the watchlist.
	ws->currentdir = cdir;
	strcpy(ws->currentdir, "__provided__");

	ws->currentfile = clin;
	strcpy(ws->currentfile, line);

	if (ws->dbtype == sqlite)
		sqlite_dbimpl_add_cpe_to_database(ws, cpe);
	else if (ws->dbtype == mysql)
		mysql_dbimpl_add_cpe_to_database(ws, cpe);

	free(cdir);
	free(clin);

	return 0;
};

/**
 * Process the (open) system list file.
 *
 * If a line contains a possible candidate (file is readable, etc.), call
 * match_binary against it.
 */
int process_binfile(char * line, struct workstate * ws) { 
	struct stat filestat;
	int rc = 0;

	if (stat(line, &filestat) < 0) {
		return 1;
	};

	if (S_ISLNK(filestat.st_mode))
		return 0;	// We don't follow symlinks, we'll get to the eventual string anyhow

	// Only follow readable files
	if (filestat.st_mode & S_IROTH) {
		rc = match_binary(line, ws);	
	};


	return rc;
};

/**
 * Reinitialize the version gathering database
 */
void clear_versiondata(struct workstate * ws) {
	if (ws->dbtype == sqlite)
		sqlite_dbimpl_clear_versiondata(ws);
	else if (ws->dbtype == mysql) 
		mysql_dbimpl_clear_versiondata(ws);
};

/**
 * Reinitialize the version database
 *
 * Basically, this will remove the previous version settings in the database so
 * that the new run can populate the database with the current version list.
 */
int clear_versiondatabase(struct workstate * ws) {
	int rc = 0;
	if (ws->dbtype == sqlite)
		rc = sqlite_dbimpl_clear_versiondatabase(ws);
	else if (ws->dbtype == mysql)
		mysql_dbimpl_clear_versiondatabase(ws);

	return rc;
};

/**
 * Load the version data information into the databases
 *
 * The version data information contains the methods for gathering version
 * information from system files. Newer versions will lead to more hits on the
 * software metering aspect of cvechecker.
 */
int load_version_data(struct workstate * ws) {
	int rc = 0;
	int linenum = 1;
	char line[VERSIONLINESIZE];

	rc = init_versiondata(ws);
	if (rc)
		return rc;

	clear_versiondata(ws);

	fprintf(stdout, "Loading in new version data file...\n");
	zero_string(line, VERSIONLINESIZE);
	while(fgets(line, VERSIONLINESIZE, ws->datafile) != NULL) {
		if (line[VERSIONLINESIZE-1] != '\0') {
			fprintf(stderr, "An error occurred while reading in version data file (linelength >= %d). Skipping line %d\n", VERSIONLINESIZE-1, linenum);
			// Reading until newline passed
			zero_string(line, VERSIONLINESIZE);
			while(fgets(line, VERSIONLINESIZE-1, ws->datafile) != NULL) {
				if (line[VERSIONLINESIZE-1] == '\0')
					break;
			};
			zero_string(line, VERSIONLINESIZE);
			linenum++;
			continue;
		};
		rc = process_versiondata(line, ws);
		if (rc) {
			fprintf(stderr, "An error occurred while reading in version data file. Skipping line %d\n", linenum);
		};
		zero_string(line, VERSIONLINESIZE);
		linenum++;
	};

	return rc;
};

/**
 * Load in the CPE data from the provided file
 *
 * The watchlist contains CPEs which should be assumed to be installed on the 
 * system (or at least be watched for vulnerabilities of any kind).
 * This allows administrators to provide CPEs for software that cvechecker
 * cannot detect yet.
 */
int load_watch_list(struct workstate * ws) {
	int rc = 0;
	int linenum = 1;
	char line[CPELINESIZE];
	int l_line = 0;

	zero_string(line, CPELINESIZE);

	rc = init_watchlist(ws);
	if (rc)
		return rc;
	
	if (!((ws->arg->deltaonly) || (ws->arg->deletedeltaonly)) && (ws->versionListCleared != 1)) {
		rc = clear_versiondatabase(ws);
		ws->versionListCleared = 1;
	}

	if (rc)
		return rc;

	if (ws->arg->deletedeltaonly) {
		fprintf(stdout, "Deleting entries related to selected CPEs\n");
	} else {
		fprintf(stdout, "Adding CPE entries\n");
	};

	while (fgets(line, sizeof(line), ws->watchlist) != NULL) {
		if (line[CPELINESIZE-1] != '\0') {
			// entry too bug
			fprintf(stderr, " ! An error occurred while reading in CPE watchlist. Skipping line %d\n", linenum);
			while (fgets(line, sizeof(line), ws->binlist) != NULL) {
				if (line[CPELINESIZE-1] == '\0')
					break;
				zero_string(line, CPELINESIZE);
			};
			zero_string(line, CPELINESIZE);
			linenum++;
			continue;
		};
		l_line = swstrlen(line);
		if (line[l_line-1] == 0x0A)
			line[l_line-1] = '\0';
		if (ws->arg->deletedeltaonly) {
			rc = delete_cpe(line, ws);
			if (rc) {
				fprintf(stderr, " ! An error occurred while interpreting CPE on line %d\n", linenum-1);
			};
		} else {
			rc = add_cpe(line, ws);
			if (rc) {
				fprintf(stderr, " ! An error occurred while interpreting CPE on line %d\n", linenum-1);
			};
		};
		zero_string(line, CPELINESIZE);
		linenum++;

	};

	return rc;
}

/**
 * Obtain the installed software from the provided system list
 *
 * The system list (passed on to the application through the -b or -f arguments)
 * contains one or more files that should be parsed by the cvechecker tool. The
 * function will attempt to read in the file and process it.
 */
int get_installed_software(struct workstate * ws) {
	int rc = 0;
	int linenum = 1;
	char line[FILENAMESIZE];
	int l_line = 0;

	zero_string(line, FILENAMESIZE);

	rc = init_binlist(ws);
	if (rc) 
		return rc;

	if (!((ws->arg->deltaonly) || (ws->arg->deletedeltaonly)) && (ws->versionListCleared != 1)) {
		rc = clear_versiondatabase(ws);
		ws->versionListCleared = 1;
	}

	if (rc)
		return rc;

	if (ws->arg->deletedeltaonly) {
		fprintf(stdout, "Deleting entries related to selected files...\n");
	} else {
		fprintf(stdout, "Searching for known software titles...\n");
	};

	while(fgets(line, sizeof(line), ws->binlist) != NULL) {
		if (line[FILENAMESIZE-1] != '\0') {
			// entry too big
			fprintf(stderr, " ! An error occurred while reading in software listing. Skipping line %d\n", linenum);
			while(fgets(line, sizeof(line), ws->binlist) != NULL) {
				if (line[FILENAMESIZE-1] == '\0')
					break;
				zero_string(line, FILENAMESIZE);
			};
			zero_string(line, FILENAMESIZE-1);
			linenum++;
			continue;
		};
		if (strchr(line, ',') != NULL) {
			// For the time being, don't allow "," in file names
			fprintf(stderr, " ! Files with comma's in their name are currently not allowed. Skipping line %d\n", linenum);
			linenum++;
			continue;
		};
		l_line = swstrlen(line);
		if (line[l_line-1] == 0x0A)
			line[l_line-1] = '\0';
		if (ws->arg->deletedeltaonly) {
			rc = delete_binfile(line, ws);
		} else {
			rc = process_binfile(line, ws);
		};
		if (rc)
			return rc;
		zero_string(line, FILENAMESIZE);
		linenum++;
	};

	return rc;
};

void report_installed(struct workstate * ws, int showfiles) {
	if (ws->arg->docsvoutput)
		fprintf(stdout, "Outputversion,Vendor,Product,Version,Update,Edition,Language,Hostname,Userkey,Files\n");
	if (ws->dbtype == sqlite)
		sqlite_dbimpl_report_installed(ws, showfiles);
	else if (ws->dbtype == mysql)
		mysql_dbimpl_report_installed(ws, showfiles);
};

/**
 * Initialize the arguments structure for further use.
 *
 * The arguments structure is a general variable that gets passed to the
 * functions that have a need to obtain the applications' arguments.
 */
void initialize_arguments(struct arguments * arg) {
	arg->parsebin = 0;
	arg->loadcve  = 0;
	arg->runcheck = 0;
	arg->binlist = NULL;
	arg->cvedata = NULL;
	arg->datafile = NULL;
	arg->watchlist = NULL;
	arg->hassinglefile = 0;
	arg->initdatabases = 0;
	arg->hasdatafile = 0;
	arg->haswatchlist = 0;
	arg->docsvoutput = 0;
	arg->doshowinstalled = 0;
	arg->doshowinstalledfiles = 0;
	arg->deltaonly = 0;
	arg->deletedeltaonly = 0;
	arg->reporthigher = 0;
};

/**
 * Load in the CVE data
 *
 * The function will parse the input file (which is a simple CSV file) and pass
 * on each entry to the database.
 */
int load_cve(struct workstate * ws) {
	FILE * cvelist = NULL;
	char buffer[BUFFERSIZE];
	char cveId[CVELINESIZE];
	char cpeId[CPELINESIZE];
	char cvssNum[6];
	char * bufferptr;
	long int ctr = 0;
	long int dup = 0;
	int linenum  = 1;
	struct arguments * arg = ws->arg;
	char field[BUFFERSIZE];
	int fieldCounter = 0;
	char tmpCpeId[3];
	char tmpCpeVendor[FIELDSIZE];
	char tmpCpeProduct[FIELDSIZE];
	char tmpCpeVersion[FIELDSIZE];
	char tmpCpeUpdate[FIELDSIZE];
	char tmpCpeEdition[FIELDSIZE];
	char tmpCpeLanguage[FIELDSIZE];

	fprintf(stdout, "Loading CVE data from %s into database\n", arg->cvedata);

	if (ws->dbtype == sqlite)
		sqlite_dbimpl_store_cve_in_db_init(ws);
	else if (ws->dbtype == mysql) {
		mysql_dbimpl_store_cve_in_db_init(ws);
	}

	cvelist = fopen(arg->cvedata, "r");
	if (cvelist == NULL) {
		fprintf(stderr, "Could not open file %s for reading: ", arg->binlist);
		perror(arg->binlist);
		return 1;
	};


	zero_string(buffer, BUFFERSIZE);
	// buffer will contain a single line from the CSV file
	while (fgets(buffer, BUFFERSIZE, cvelist) != 0) {
		zero_string(tmpCpeId, 3);
		zero_string(tmpCpeVendor, FIELDSIZE);
		zero_string(tmpCpeProduct, FIELDSIZE);
		zero_string(tmpCpeVersion, FIELDSIZE);
		zero_string(tmpCpeUpdate, FIELDSIZE);
		zero_string(tmpCpeEdition, FIELDSIZE);
		zero_string(tmpCpeLanguage, FIELDSIZE);

		// Overflow?
		if (buffer[BUFFERSIZE-1] != '\0') {
			fprintf(stderr, " ! Error while reading in CVE entries.  Skipping line %d (too long)\n", linenum);
			while (fgets(buffer, BUFFERSIZE, cvelist) != 0) {
				if (buffer[BUFFERSIZE-1] == '\0')
					break;
			};
			zero_string(buffer, BUFFERSIZE);
			linenum++;
		};

		// Reset trailing newline (if available)
		if ((bufferptr = strchr(buffer, '\n')) != NULL)
			*bufferptr = '\0';

		bufferptr = buffer;
		fieldCounter = 0;

		// Split based on ':' character
		int invalid_line = 0;
		while (sscanf(bufferptr, "%[^:]s", field) == 1) {
			int fieldLength = swstrlen(field);	// Capture field length up front as strtok_r modifies the string
			if (fieldCounter == 0) {
				// Should be "CVE-####-####+" (CVE identifier)
				char * sCVE;
				char * token;
				char * substring;
				unsigned int iYear;
				unsigned int iID;

				// Tokenize based on - delimiter.
				// Token 1 = CVE (literal)
				sCVE = strtok_r(field, "-", &token);
				if (sCVE == NULL) {
					// NULL obtained
					fprintf(stderr, " ! Error while reading in CVE entries: CVE field in line %d failed to obtain CVE string\n", linenum);
					return 1;
				};

				// Token 2 = CVE year (integer)
				substring = strtok_r(NULL, "-", &token);
				if (substring == NULL) {
					// NULL obtained
					fprintf(stderr, " ! Error while reading in CVE entries: CVE year in line %d failed to be parsed\n", linenum);
					return 1;
				};
				iYear = atoi(substring);				

				// Token 3 = CVE sequence (integer)
				substring = strtok_r(NULL, "-", &token);
				if (substring == NULL) {
					// NULL obtained
					fprintf(stderr, " ! Error while reading in CVE entries: CVE sequence in line %d failed to be parsed\n", linenum);
					return 1;
				};
				iID = atoi(substring);

				// Rewrite the string (now we know for sure it is correct format)
				snprintf(cveId, CVELINESIZE, "CVE-%d-%d", iYear, iID);

			} else if (fieldCounter == 1) {
				// Should be [0-9]+.[0-9]+ (score)
				unsigned int iPre;
				unsigned int iPost;
				if (sscanf(field, "%u.%u", &iPre, &iPost) != 2) {
					// Not both fields were correctly assigned
					fprintf(stderr, " ! Error while reading in CVE entries: CVSS score in line %d did not match expected format\n", linenum);
					return 1;
				}
				snprintf(cvssNum, 6, "%u.%u", iPre, iPost);

			} else if (fieldCounter == 2) {
				// Should be "cpe"
				if (strncmp(field, "cpe", 3) != 0) {
					fprintf(stderr, " ! Error while reading in CVE entries: expected 'cpe' string did not occur in line %d\n", linenum);
					return 1;
				}
			} else if (fieldCounter == 3) {
				// Should be "/a", "/o" or "/h" (app, operating system or hardware)
				if (
					(strncmp(field, "/a", 2) != 0) &&
					(strncmp(field, "/o", 2) != 0) &&
					(strncmp(field, "/h", 2) != 0) ) {
					fprintf(stderr, " ! Error while reading in CVE entries: CPE type in line %d is not one of a/o/h\n", linenum);
					invalid_line = 1;
					break;
				}
				snprintf(tmpCpeId, 3, "%s", field);

			} else if (fieldCounter >= 4) {
				// Should be a string (vendor, software title, version, edition or language)
				int ptr = 0;
				while(field[ptr] != 0) {
					if (! isgraph(field[ptr]) ) {
						fprintf(stderr, " ! Error while reading in CVE entries: information in the CPE of line %d is not readable\n", linenum);
						return 1;
					}
					ptr++;
				}
				if (fieldCounter == 4)
					snprintf(tmpCpeVendor, FIELDSIZE, "%s", field);
				if (fieldCounter == 5)
					snprintf(tmpCpeProduct, FIELDSIZE, "%s", field);
				if (fieldCounter == 6)
					snprintf(tmpCpeVersion, FIELDSIZE, "%s", field);
				if (fieldCounter == 7)
					snprintf(tmpCpeUpdate, FIELDSIZE, "%s", field);
				if (fieldCounter == 8)
					snprintf(tmpCpeEdition, FIELDSIZE, "%s", field);
				if (fieldCounter == 9)
					snprintf(tmpCpeLanguage, FIELDSIZE, "%s", field);

			}

			bufferptr = bufferptr + fieldLength + 1;
			++fieldCounter;
		}
		if (invalid_line)
			continue;
		// Build the CPE up
		snprintf(cpeId, CPELINESIZE, "cpe:%s:%s:%s:%s:%s:%s:%s", tmpCpeId, tmpCpeVendor, tmpCpeProduct, tmpCpeVersion, tmpCpeUpdate, tmpCpeEdition, tmpCpeLanguage);

		// Now load in the data in the database
		if (ws->dbtype == sqlite)
			dup += sqlite_dbimpl_store_cve_in_db(ws, cveId, cpeId, cvssNum);
		else if (ws->dbtype == mysql)
			dup += mysql_dbimpl_store_cve_in_db(ws, cveId, cpeId, cvssNum);
		ctr++;
		if ((ctr % 100) == 0) {
			fprintf(stdout, " %ld records processed (%ld already in db)...\n", ctr, dup);
			if (ws->dbtype == sqlite)
				sqlite_dbimpl_store_cve_in_db_checkpoint(ws);
			else if (ws->dbtype == mysql)
				mysql_dbimpl_store_cve_in_db_checkpoint(ws);
		};
		linenum++;
		zero_string(buffer, BUFFERSIZE);
	};

	if (ws->dbtype == sqlite)
		sqlite_dbimpl_store_cve_in_db_exit(ws);
	else if (ws->dbtype == mysql)
		mysql_dbimpl_store_cve_in_db_exit(ws);

	fprintf(stdout, " %ld records processed (%ld already in db)...\n", ctr, dup);

	fclose(cvelist);

	return 0;
		
};

/**
 * Parse the arguments of the application
 *
 * This is a mandatory method that needs to be defined when you use argp.
 */
static error_t parse_opt (int key, char * arg, struct argp_state *state) {
	struct arguments * arguments = state->input;
	switch(key) {
	  case 'b':
	    arguments->binlist = arg;
	    arguments->parsebin = 1;
	    break;
	  case 'd':
	    arguments->deltaonly = 1;
	    break;
	  case 'D':
	    arguments->deletedeltaonly = 1;
	    break;
	  case 'c':
	    arguments->cvedata = arg;
	    arguments->loadcve = 1;
	    break;
	  case 'r':
	    arguments->runcheck = 1;
	    break;
	  case 'f':
	    arguments->singlefile = arg;
	    arguments->hassinglefile = 1;
	    break;
	  case 'l':
	    arguments->datafile = arg;
	    arguments->hasdatafile = 1;
	    break;
	  case 'w':
	    arguments->watchlist = arg;
	    arguments->haswatchlist = 1;
	    break;
	  case 'i':
	    arguments->initdatabases = 1;
	    break;
	  case 'C':
	    arguments->docsvoutput = 1;
	    break;
	  case 's':
	    arguments->doshowinstalled = 1;
	    break;
	  case 'S':
	    arguments->doshowinstalledfiles = 1;
	    break;
	  case 'H':
	    arguments->reporthigher = 1;
	    break;
	  default:
	    return ARGP_ERR_UNKNOWN;
	};
	return 0;
};

/** 
 * Main function of the cvechecker tool
 */
int main(int argc, char ** argv) {
	struct arguments arguments;
	struct workstate workstate;
	int rc = 0;

	initialize_arguments(&arguments);
	initialize_workstate(&workstate, &arguments);

	argp_parse(&argp, argc, argv, 0, 0, &arguments);

	rc = arguments.parsebin + arguments.loadcve + arguments.runcheck + arguments.hassinglefile + arguments.hasdatafile + arguments.initdatabases + arguments.doshowinstalled + arguments.doshowinstalledfiles + arguments.haswatchlist;
	if (rc == 0) {
		argp_help(&argp, stdout, ARGP_HELP_USAGE, argv[0]);
		exit(EXIT_FAILURE);
	}

	rc = arguments.deltaonly + arguments.deletedeltaonly;
	if (rc > 1) {
		fprintf(stderr, "Options -d (--deltaonly) and -D (--deletedeltaonly) are mutually exclusive!\n");
		exit(EXIT_FAILURE);
	}

	rc = load_databases(&workstate);
	if (rc) 
		exit(EXIT_FAILURE);


	// Administrative task - Exceptional rights
	if (arguments.initdatabases == 1)
		initialize_databases(&workstate);
	// Administrative task
	if (arguments.hasdatafile)
		load_version_data(&workstate);
	// Operational task
	if (arguments.parsebin) 
		get_installed_software(&workstate);
	// Operational task
	if (arguments.haswatchlist)
		rc = load_watch_list(&workstate);

	if (rc)
		exit(EXIT_FAILURE);

	// Administrative task
	if (arguments.loadcve)
		rc = load_cve(&workstate);
	
	if (rc)
		exit(EXIT_FAILURE);

	// Operational task
	if (arguments.hassinglefile)
		match_binary(arguments.singlefile, &workstate);
	// Reporting task
	if (arguments.doshowinstalled || arguments.doshowinstalledfiles) 
		report_installed(&workstate, arguments.doshowinstalledfiles);
	// Reporting task
	if (arguments.runcheck)
		verify_installed_versus_cve(&workstate);

	exit(EXIT_SUCCESS);
}
