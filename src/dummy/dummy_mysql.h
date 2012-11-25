/*
 * Copyright 2010,2011 Sven Vermeulen.
 * Subject to the GNU Public License, version 3.
 */

#ifndef CVECHECKER_MYSQL_IMPL_H
#define CVECHECKER_MYSQL_IMPL_H

#include "../cvecheck_common.h"

// mysql_dbimpl_initialize_workstate - Initialize the workstate variable
int mysql_dbimpl_initialize_workstate(struct workstate * ws);

// mysql_dbimpl_load_databases - Load the databases into the workstate
int mysql_dbimpl_load_databases(struct workstate * ws);

// mysql_dbimpl_clear_versiondatabase - Clear the version database
int mysql_dbimpl_clear_versiondatabase(struct workstate * ws);

// mysql_dbimpl_clear_versiondata - Clear the version gathering data
int mysql_dbimpl_clear_versiondata(struct workstate * ws);

// mysql_dbimpl_delete_binary - Delete the binary files
int mysql_dbimpl_delete_binary(struct workstate * ws);

// mysql_dbimpl_process_binary - Process the binary file as mentioned in the workstate 
int mysql_dbimpl_process_binary(struct workstate * ws);

// mysql_dbimpl_verify_installed_versus_cve - Match installed software against known CVEs
int mysql_dbimpl_verify_installed_versus_cve(struct workstate * ws);

// mysql_dbimpl_initialize_arguments - Initialize arguments structure
int mysql_dbimpl_initialize_arguments(struct arguments * arg);

// mysql_dbimpl_store_cve_in_db_init - Initialize CVE entry
int mysql_dbimpl_store_cve_in_db_init(struct workstate * ws);

// mysql_dbimpl_store_cve_in_db_exit - Finalize CVE entry
int mysql_dbimpl_store_cve_in_db_exit(struct workstate * ws);

// mysql_dbimpl_store_cve_in_db_checkpoint - Checkpoint for CVE upload
int mysql_dbimpl_store_cve_in_db_checkpoint(struct workstate * ws);

// mysql_dbimpl_store_cve_in_db - Add the selected CVE into the database
int mysql_dbimpl_store_cve_in_db(struct workstate * ws, char * cveId, char * cpeId, char * cvssNum);

// mysql_dbimpl_add_versiongather - Add a versiongather entry into the database
int mysql_dbimpl_add_versiongather(struct workstate * ws, struct versiongather_data vg, struct cpe_data cpe);

// mysql_dbimpl_initialize_databases - Initialize the database structures
int mysql_dbimpl_initialize_databases(struct workstate * ws);

// mysql_dbimpl_report_installed - Report on installed software/versions
int mysql_dbimpl_report_installed(struct workstate * ws, int showfiles);

// mysql_dbimpl_add_to_database - Add a CPE to the database immediately
int mysql_dbimpl_add_cpe_to_database(struct workstate * ws, struct cpe_data cpe);

// mysql_dbimpl_supported - Check if mysql support is built in
int mysql_dbimpl_supported();

#endif
