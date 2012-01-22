#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <regex.h>
#include "../swstring.h"
#include "../cvecheck_common.h"
#include "../output/stringscmd.h"

/*
 * Copyright 2010,2011 Sven Vermeulen.
 * Subject to the GNU Public License, version 3.
 */

#ifndef CVECHECKER_SQLITE_IMPL_H
#define CVECHECKER_SQLITE_IMPL_H

/*
 * Helper macro's for database operations
 */

#define PREPARE_SQLITE(rc, db, stmt, sqlstmt) \
  rc = sqlite3_prepare_v2(db, stmt, -1, &sqlstmt, NULL); \
  if (rc != SQLITE_OK) { \
    fprintf(stderr, "Failed to prepare statement \"%s\".\n", stmt); \
    exit(EXIT_FAILURE); \
  };

// rc (int), stmt (char *) intstmt (sqlite3_stmt *)

#define ASSERT_FINALIZE(rc, stmt, intstmt) \
  if (rc != SQLITE_DONE) { \
    fprintf(stderr, "Sqlite3 failed to finish step() correctly, returned code %d\n", rc); \
    exit(EXIT_FAILURE); \
  } else { \
    rc = sqlite3_finalize(intstmt); \
    if (rc != SQLITE_OK) { \
      fprintf(stderr, "Failed to finalize statement \"%s\".\n", stmt); \
      exit(EXIT_FAILURE); \
    }; \
  };

// rc (int), db (sqlite3_db *), stmt (char *), func (void *())

#define EXEC_SQLITE(rc, db, stmt, func) \
  rc = sqlite3_exec(db, stmt, func, ws, &errmsg); \
  if (rc != SQLITE_OK) { \
    fprintf(stderr, "Failed to execute statement \"%s\".\n", stmt); \
    fprintf(stderr, "SQLite3 returned with error: %s\n", errmsg); \
    sqlite3_free(errmsg); \
  };

// rc (int), db (sqlite3_db *), stmt (char *), func (void *())

#define EXEC_SQLITE_RETURNFAIL(rc, db, stmt, func) \
  rc = sqlite3_exec(db, stmt, func, ws, &errmsg); \
  if (rc != SQLITE_OK) { \
    fprintf(stderr, "Failed to execute statement \"%s\".\n", stmt); \
    fprintf(stderr, "SQLite3 returned with error: %s\n", errmsg); \
    sqlite3_free(errmsg); \
    return rc; \
  };


// sqlite_dbimpl_initialize_workstate - Initialize the workstate variable
int sqlite_dbimpl_initialize_workstate(struct workstate * ws);

// sqlite_dbimpl_load_databases - Load the databases into the workstate
int sqlite_dbimpl_load_databases(struct workstate * ws);

// sqlite_dbimpl_clear_versiondatabase - Clear the version database
int sqlite_dbimpl_clear_versiondatabase(struct workstate * ws);

// sqlite_dbimpl_clear_versiondata - Clear the version gathering data
int sqlite_dbimpl_clear_versiondata(struct workstate * ws);

// sqlite_dbimpl_delete_binary - Delete the binary files
int sqlite_dbimpl_delete_binary(struct workstate * ws);

// sqlite_dbimpl_process_binary - Process the binary file as mentioned in the workstate 
int sqlite_dbimpl_process_binary(struct workstate * ws);

// sqlite_dbimpl_verify_installed_versus_cve - Match installed software against known CVEs
int sqlite_dbimpl_verify_installed_versus_cve(struct workstate * ws);

// sqlite_dbimpl_initialize_arguments - Initialize arguments structure
int sqlite_dbimpl_initialize_arguments(struct arguments * arg);

// sqlite_dbimpl_store_cve_in_db_init - Initialize CVE entry
int sqlite_dbimpl_store_cve_in_db_init(struct workstate * ws);

// sqlite_dbimpl_store_cve_in_db_exit - Finalize CVE entry
int sqlite_dbimpl_store_cve_in_db_exit(struct workstate * ws);

// sqlite_dbimpl_store_cve_in_db_checkpoint - Checkpoint CVE upload
int sqlite_dbimpl_store_cve_in_db_checkpoint(struct workstate * ws);

// sqlite_dbimpl_store_cve_in_db - Add the selected CVE into the database
int sqlite_dbimpl_store_cve_in_db(struct workstate * ws, char * cveId, char * cpeId, char * cvssNum);

// sqlite_dbimpl_add_versiongather - Add a versiongather entry into the database
int sqlite_dbimpl_add_versiongather(struct workstate * ws, struct versiongather_data vg, struct cpe_data cpe);

// sqlite_dbimpl_initialize_databases - Initialize the database structures
int sqlite_dbimpl_initialize_databases(struct workstate * ws);

// sqlite_dbimpl_report_installed - Report on installed software/versions
int sqlite_dbimpl_report_installed(struct workstate * ws, int showfiles);

// sqlite_dbimpl_add_to_database - Add a CPE to the database immediately
int sqlite_dbimpl_add_cpe_to_database(struct workstate * ws, struct cpe_data cpe);

// sqlite_dbimpl_supported - Is sqlite support built-in?
int sqlite_dbimpl_supported();

#endif
