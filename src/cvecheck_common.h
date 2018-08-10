#include <stdio.h>
#include <libconfig.h>

#ifdef _USE_SQLITE3
#include <sqlite3.h>
#endif

#ifdef _USE_MYSQL
#include <mysql/mysql.h>
#endif

/*
 * Copyright 2010-2013 Sven Vermeulen.
 * Subject to the GNU Public License, version 3.
 */
 
#ifndef _CVETYPES
#define _CVETYPES

#define FIELDSIZE 128
#define LARGEFIELDSIZE 512
#define FILENAMESIZE 256
#define BUFFERSIZE 256
#define CVELINESIZE 24 
#define CPELINESIZE (7 + FIELDSIZE*6 + 5)
#define VERSIONLINESIZE (FILENAMESIZE*2 + 5 + CPELINESIZE)
// Normally, around 1800 ought to be enough (largest SELECT statement with assumption of largest values)
#define SQLLINESIZE 4096

enum database_types {
  sqlite,
  mysql
};

struct arguments {
	char * args;
	char * binlist;
	char * cvedata;
	char * singlefile;
	char * datafile;
	char * watchlist;
	int parsebin;
	int loadcve;
	int runcheck;
	int hassinglefile;
	int hasdatafile;
	int haswatchlist;
	int initdatabases;
	int docsvoutput;
	int doshowinstalled;
	int doshowinstalledfiles;
	int deltaonly;
	int deletedeltaonly;
	int reporthigher;
};

struct cpe_data {
	char part;
	char vendor[FIELDSIZE];
	char product[FIELDSIZE];
	char version[FIELDSIZE];
	char update[FIELDSIZE];
	char edition[FIELDSIZE];
	char language[FIELDSIZE];
};

struct workstate {
	struct arguments * arg;
	FILE * binlist;
	FILE * datafile;
	FILE * watchlist;
	char * currentdir;
	char * currentfile;
	char * hostname;
	char * userdefkey;
	config_t * cfg;
	struct cpe_data cpebuffer;
	void ** resultlist;
	int numresults;
	int rc;
	int versionListCleared;
	enum database_types dbtype;
#ifdef _USE_SQLITE3
	sqlite3 * matchdb;
	sqlite3 ** localdb;
#endif
#ifdef _USE_MYSQL
	MYSQL * conn;
#endif
};

struct versiongather_data {
	char filepart[FILENAMESIZE];
	int gathertype;
	char filematch[FILENAMESIZE];
	char versionexpression[LARGEFIELDSIZE];
};

/***********************************************************************************************
 * CPE related definitions
 ***********************************************************************************************/

// cpe_to_string - Convert the selected cpe_data structure to a string
void cpe_to_string(char * buffer, int buffsize, struct cpe_data cpe);

// string_to_cpe - Convert the selected cpe string (buffer) to a structure
void string_to_cpe(struct cpe_data * cpe, char * buffer);

// cve_to_vars - Convert the cve identifier (string) to a year/sequence combination
int cve_to_vars(int * year, int * sequence, char * cveId);

// show_potential_vulnerabilities - Show the potential vulnerability matches
void show_potential_vulnerabilities(struct workstate * ws, int cveyear, int cvenum, int cvssScore, const char * filename, struct cpe_data cpe, int versiononly);

// show_installed_software - Show the installed software
void show_installed_software(struct workstate * ws, const char * vendor, const char * product, const char * version, const char * update, const char * edition, const char * language, int numfiles, const char ** files);

// clear_resultlist - Clear workstate result list
void clear_resultlist(struct workstate * ws);

// get_version_field - Get the field (int) value from a version string (first field = 0)
int get_version_field(const char * version, int fieldnum);

#endif
