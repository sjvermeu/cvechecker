#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <regex.h>
#include <unistd.h>
#include <stdlib.h>
#include <argp.h>
#include <errno.h>
#include <libconfig.h>

/*
 * Copyright 2010-2017 Sven Vermeulen.
 * Subject to the GNU Public License, version 3.
 */
 
// parse_opt - Parse the arguments
static error_t parse_opt (int key, char * arg, struct argp_state *state);

#include "swstring.h"
#include "cvecheck_common.h"

/***********************************************************************************************
 * Database Selection
 ***********************************************************************************************/
#ifdef _USE_SQLITE3
#include "sqlite3/sqlite3_impl.h"
#else
#include "dummy/dummy_sqlite3.h"
#endif

#ifdef _USE_MYSQL
#include "mysql/mysql_impl.h"
#else
#include "dummy/dummy_mysql.h"
#endif

const char * argp_program_version     = "cvechecker 3.9";
const char * argp_program_bug_address = "<sven.vermeulen@siphos.be>";

static char doc[]      = "cvechecker -- Verify the state of the system against a CVE database";
static char args_doc[] = "";

static struct argp_option options[] = {
	{"binlist", 'b', "binlist", 0, "List of binary files on the system" },
	{"watchlist", 'w', "watchlist", 0, "List of CPEs to watch for (assume these are installed)" },
	{"cvedata", 'c', "cvefile", 0, "CSV file with CVE information (cfr. nvd2simple)" },
	{"loaddata", 'l', "datafile", 0, "Load version gathering data file" },
	{"runcheck", 'r', 0, 0, "Execute the checks (match installed software with CVEs)" }, 
	{"reporthigher", 'H', 0, 0, "Report also when CVEs have been detected for higher versions" },
	{"fileinfo", 'f', "binfile", 0, "File to obtain detected CPE of" },
	{"initdbs", 'i', 0, 0, "Initialize all databases" },
	{"csvoutput", 'C', 0, 0, "Use (parseable) CSV output" },
	{"showinstalled", 's', 0, 0, "Output detected software/versions" },
	{"showinstalledfiles", 'S', 0, 0, "Output detected software/versions with file information" },
	{"deltaonly", 'd', 0, 0, "Given binaries or lists should be added only (not a full replacement)" },
	{"deletedeltaonly", 'D', 0, 0, "Given binaries or lists should be removed (not a full replacement)" },
	{ 0 }
};

static struct argp argp = { options, parse_opt, args_doc, doc };

// find_match_in_file - Find a string match in a (binary) file
void find_match_in_file(struct workstate * ws, regex_t * preg, regmatch_t * pmatch, struct cpe_data cpe);

// get_db_count - Return the count(*) value of the caller SQL statement
int get_db_count(void * cbobj, int argc, char **argv, char **azColName);

// file_already_processed - Validate if the given file has already been processed succesfully
int file_already_processed(struct workstate * ws);

// get_version_and_store - For each match, verify if the file matches. If it does, also content-wise, store the results in the local db
int get_version_and_store(void * cbobj, int argc, char **argv, char **azColName);

// load_databases - Initialize databases
int load_databases(struct workstate * ws);

// init_binlist - Initialize binary listing file
int init_binlist(struct workstate * ws);

// match_binary - For a single selected filename, verify if it can possibly match a known binary
int match_binary(char * file, struct workstate * ws);

// process_binfile - If the selected file is a binary, readable file, process it
int process_binfile(char * line, struct workstate * ws);

// delete_binfile - Delete the binary file from the database
int delete_binfile(char * line, struct workstate * ws);

// clear_versiondatabase - Purse the local database
int clear_versiondatabase(struct workstate * ws);

// get_installed_software - Read the list of installed binaries and process the list
int get_installed_software(struct workstate * ws);

// load_cve - Load CVE data from XML file into the database
int load_cve(struct workstate * ws);

// verify_installed_versus_cve - Match the installed software against the known CVE vulnerabilities
void verify_installed_versus_cve(struct workstate * ws);

// initialize_arguments - Initialize the arguments OKOK
void initialize_arguments(struct arguments * arg);

// initialize_workstate - Initialize the workstate variable OKOK
int initialize_workstate(struct workstate * ws, struct arguments * arg);
