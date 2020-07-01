#include "mysql_impl.h"

/*
 * Copyright 2011-2020 Sven Vermeulen.
 * Subject to the GNU Public License, version 3.
 */
 

/***********************************************************************************************
 * Helper functions for the mysql database manipulations
 ***********************************************************************************************/

/**
 * Clear the version database.
 */
int mysql_dbimpl_clear_versiondatabase(struct workstate * ws) {
  char stmt[SQLLINESIZE];

  sprintf(stmt, "DELETE FROM tb_binmatch WHERE hostname = \"%s\" AND userdefkey = \"%s\";", ws->hostname, ws->userdefkey);
  MYSQL_QUERY(ws->conn, stmt);
  return 0;
};

/**
 * Clear the version gathering data
 */
int mysql_dbimpl_clear_versiondata(struct workstate * ws) {
  MYSQL_QUERY(ws->conn, "delete from tb_versionmatch")
  return 0;
};

/**
 * Load the databases into the workstate
 */
int mysql_dbimpl_load_databases(struct workstate * ws) {
  const config_setting_t * confkey;
  char dbname[FIELDSIZE];
  char dbuser[FIELDSIZE];
  char dbpass[FIELDSIZE];
  char dbhost[FIELDSIZE];
  MYSQL * connection;
  int rc;

  zero_string(dbname, FIELDSIZE);
  zero_string(dbuser, FIELDSIZE);
  zero_string(dbpass, FIELDSIZE);
  zero_string(dbhost, FIELDSIZE);


  confkey = config_lookup(ws->cfg, "mysql.dbname");
  if (confkey == NULL) {
    fprintf(stderr, "Configuration file does not contain mysql.dbname directive.\n");
    return 1;
  };
  rc = strlen(config_setting_get_string(confkey));
  if (rc > FIELDSIZE-1) {
    fprintf(stderr, "Configuration files 'mysql.dbname' directive cannot exceed %d characters\n", FIELDSIZE-1);
    return 1;
  };
  strncpy(dbname, config_setting_get_string(confkey), rc);

  confkey = config_lookup(ws->cfg, "mysql.dbuser");
  if (confkey == NULL) {
    fprintf(stderr, "Configuration file does not contain mysql.dbuser directive.\n");
    return 1;
  };
  rc = strlen(config_setting_get_string(confkey));
  if (rc > FIELDSIZE-1) {
    fprintf(stderr, "Configuration files 'mysql.dbuser' directive cannot exceed %d characters\n", FIELDSIZE-1);
    return 1;
  };
  strncpy(dbuser, config_setting_get_string(confkey), rc);

  confkey = config_lookup(ws->cfg, "mysql.dbpass");
  if (confkey == NULL) {
    fprintf(stderr, "Configuration file does not contain mysql.dbpass directive.\n");
    return 1;
  };
  rc = strlen(config_setting_get_string(confkey));
  if (rc > FIELDSIZE-1) {
    fprintf(stderr, "Configuration files 'mysql.dbpass' directive cannot exceed %d characters\n", FIELDSIZE);
    return 1;
  };
  strncpy(dbpass, config_setting_get_string(confkey), rc);

  confkey = config_lookup(ws->cfg, "mysql.dbhost");
  if (confkey == NULL) {
    fprintf(stderr, "Configuration file does not contain mysql.dbhost directive.\n");
    return 1;
  };
  rc = strlen(config_setting_get_string(confkey));
  if (rc > FIELDSIZE-1) {
    fprintf(stderr, "Configuration files 'mysql.dbhost' directive cannot exceed %d characters\n", FIELDSIZE);
    return 1;
  };
  strncpy(dbhost, config_setting_get_string(confkey), rc);

  connection = mysql_real_connect(ws->conn, dbhost, dbuser, dbpass, dbname, 0, NULL, 0);
  if (connection == NULL) {
    fprintf(stderr, "Error %u: %s\n", mysql_errno(ws->conn), mysql_error(ws->conn));
    return 1;
  } else {
    return 0;
  };
};

/**
 * Add the selected CPE to the database
 */
int mysql_dbimpl_add_cpe_to_database(struct workstate * ws, struct cpe_data cpe) {
  char buffer[BUFFERSIZE];
  int rc;

  rc = add_to_mysql_database(ws, cpe);
  update_binmatch_files(ws, rc);
  cpe_to_string(buffer, BUFFERSIZE, cpe);
  fprintf(stdout, " - Added watch for %s\n", buffer);

  return 0;
};

/**
 * Delete the binary
 *
 * The binary file is provided through the workstate variable (currentfile and 
 * currentdir properties).
 */
int mysql_dbimpl_delete_binary(struct workstate * ws) {
  char buffer[BUFFERSIZE];

  sprintf(buffer, "delete from tb_binmatch where basedir = \"%s\" and filename = \"%s\" and hostname = \"%s\" and userdefkey = \"%s\";", ws->currentdir, ws->currentfile, ws->hostname, ws->userdefkey);
  
  MYSQL_QUERY(ws->conn, buffer)
  return 0;
};

/**
 * add_to_mysql_database - Add the selected CPE to the database
 *
 * CPEs are used in various places, so adding the CPE is more than adding it to the tb_cpe table.
 * We also need to add the proper information in tb_cpe_parents, but always make sure that we don't
 * insert duplicate values anywhere either.
 */
int add_to_mysql_database(struct workstate * ws, struct cpe_data cpe) {
  int rc = 0;
  char stmt[SQLLINESIZE];
  char cpeversion[FIELDSIZE];
  char cpeupdate[FIELDSIZE];
  char cpeedition[FIELDSIZE];
  char cpelanguage[FIELDSIZE];
  char cpeswedition[FIELDSIZE];
  char cpetargetsw[FIELDSIZE];
  char cpetargethw[FIELDSIZE];
  char cpeother[FIELDSIZE];
  MYSQL_RES * result;
  MYSQL_ROW row;

  mysql_real_escape_string(ws->conn, cpeversion, cpe.version, swstrlen(cpe.version));
  mysql_real_escape_string(ws->conn, cpeupdate, cpe.update, swstrlen(cpe.update));
  mysql_real_escape_string(ws->conn, cpeedition, cpe.edition, swstrlen(cpe.edition));
  mysql_real_escape_string(ws->conn, cpelanguage, cpe.language, swstrlen(cpe.language));
  mysql_real_escape_string(ws->conn, cpeswedition, cpe.swedition, swstrlen(cpe.swedition));
  mysql_real_escape_string(ws->conn, cpetargetsw, cpe.targetsw, swstrlen(cpe.targetsw));
  mysql_real_escape_string(ws->conn, cpetargethw, cpe.targethw, swstrlen(cpe.targethw));
  mysql_real_escape_string(ws->conn, cpeother, cpe.other, swstrlen(cpe.other));

  /*
   * First, we check if we already have an entry in tb_cpe for this CPE. If we do, then we can just return
   * this ID and do not have to do anything else.
   */
  sprintf(stmt, "select cpeid from tb_cpe where cpepart = \"%c\" and cpevendor = \"%s\" and cpeproduct = \"%s\" and cpeversion = \"%s\" and cpeupdate = \"%s\" and cpeedition = \"%s\" and cpelanguage = \"%s\" and cpeswedition = \"%s\" and cpetargetsw = \"%s\" and cpetargethw = \"%s\" and cpeother = \"%s\";", cpe.part, cpe.vendor, cpe.product, cpeversion, cpeupdate, cpeedition, cpelanguage, cpeswedition, cpetargetsw, cpetargethw, cpeother);
  MYSQL_QUERY(ws->conn, stmt)
  result = mysql_store_result(ws->conn);
  row = mysql_fetch_row(result);
  if (row != NULL) {
    rc = atoi(row[0]);
    mysql_free_result(result);
    return rc;
  };

  /*
   * So, the check failed - now we can insert the appropriate value(s) where necessary.
   * We first insert the CPE in the tb_cpe table. Then we check if the inserted version
   * information (like "2.0.34-rc3") is known in the tb_cpe_versions table. If not, then
   * the version is decomposed into its individual version fields and inserted too.
   */
  sprintf(stmt, "insert into tb_cpe (cpepart, cpevendor, cpeproduct, cpeversion, cpeupdate, cpeedition, cpelanguage, cpeswedition, cpetargetsw, cpetargethw, cpeother) values (\"%c\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\");", cpe.part, cpe.vendor, cpe.product, cpeversion, cpeupdate, cpeedition, cpelanguage, cpeswedition, cpetargetsw, cpetargethw, cpeother);
  MYSQL_QUERY(ws->conn, stmt)

  zero_string(stmt, SQLLINESIZE);
  sprintf(stmt, "select count(cpeversion) from tb_cpe_versions where cpeversion = \"%s\";", cpeversion);
  MYSQL_QUERY(ws->conn, stmt)
  result = mysql_store_result(ws->conn);
  row = mysql_fetch_row(result);
  rc = atoi(row[0]);
  mysql_free_result(result);

  if (rc == 0) {
    int f[15];
    int c;
    for (c = 0; c < 15; c++)
      f[c] = get_version_field(cpeversion, c);
    zero_string(stmt, SQLLINESIZE);
    sprintf(stmt, "INSERT INTO tb_cpe_versions (cpeversion, f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, f14, f15) values (\"%s\", %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d);", cpeversion, f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[9], f[10], f[11], f[12], f[13], f[14]);
    MYSQL_QUERY(ws->conn, stmt)
  };

  /*
   * We now gather the cpeid from tb_cpe (the automatically assigned ID after we inserted the value) as
   * we now need this information to update the tb_cpe_parents table (but also return the value to the
   * caller).
   */
  sprintf(stmt, "select cpeid from tb_cpe where cpepart = \"%c\" and cpevendor = \"%s\" and cpeproduct = \"%s\" and cpeversion = \"%s\" and cpeupdate = \"%s\" and cpeedition = \"%s\" and cpelanguage = \"%s\" and cpeswedition = \"%s\" and cpetargetsw = \"%s\" and cpetargethw = \"%s\" and cpeother = \"%s\";", cpe.part, cpe.vendor, cpe.product, cpeversion, cpeupdate, cpeedition, cpelanguage, cpeswedition, cpetargetsw, cpetargethw, cpeother);
  MYSQL_QUERY(ws->conn, stmt)
  result = mysql_store_result(ws->conn);
  row = mysql_fetch_row(result);
  if (row == NULL) {
    mysql_free_result(result);
    fprintf(stderr, "Could not find cpeid for cpe:2.3:%c:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s\n", cpe.part, cpe.vendor, cpe.product, cpeversion, cpeupdate, cpeedition, cpelanguage, cpeswedition, cpetargetsw, cpetargethw, cpeother);
    return 1;
  };
  mysql_free_result(result);
  rc = atoi(row[0]);

  /*
   * Only if the newly added CPE has a update/edition/language set, then we need to generate its master CPE information too.
   */
  if ((swstrlen(cpeupdate) > 0) || (swstrlen(cpeedition) > 0) || (swstrlen(cpelanguage) > 0) || (swstrlen(cpeswedition) > 0) || (swstrlen(cpetargetsw) > 0) || (swstrlen(cpetargethw) > 0) || (swstrlen(cpeother) > 0)) {
    // Add (if necessary) the master CPE information to the database.
    struct cpe_data parentcpe; 
    int parent = 0;
    copy_cpe_bare(&parentcpe, &cpe);
    parent = add_to_mysql_database(ws, parentcpe);

    // Now insert the current CPE to tb_cpe_parents with the new parent information.
    sprintf(stmt, "select mastercpe from tb_cpe_parents where childcpe = %d;", rc);
    MYSQL_QUERY(ws->conn, stmt);
    result = mysql_store_result(ws->conn);
    row = mysql_fetch_row(result);
    if (row == NULL) {
      mysql_free_result(result);
      sprintf(stmt, "insert into tb_cpe_parents (mastercpe, childcpe) values (%d, %d);", parent, rc);
      MYSQL_QUERY(ws->conn, stmt);
    } else {
      mysql_free_result(result);
    };
  };

  return rc;
};

/**
 * update_binmatch_files - Update the tb_binmatch table with (new) cpeids
 */
int update_binmatch_files(struct workstate * ws, int cpeid) {
  char stmt[SQLLINESIZE];
 
  // Can't use UPDATE syntax here as it is not certain that a line was already present (UPDATE doesn't INSERT if there was no line)
  sprintf(stmt, "delete from tb_binmatch where basedir = \"%s\" and filename = \"%s\" and hostname = \"%s\" and userdefkey = \"%s\";", ws->currentdir, ws->currentfile, ws->hostname, ws->userdefkey);
  MYSQL_QUERY(ws->conn, stmt)
  sprintf(stmt, "insert into tb_binmatch (basedir, filename, cpe, fullmatch, hostname, userdefkey) values (\"%s\", \"%s\", %d, 1, \"%s\", \"%s\")", ws->currentdir, ws->currentfile, cpeid, ws->hostname, ws->userdefkey);
  MYSQL_QUERY(ws->conn, stmt)
};


/**
 * Process the binary
 *
 * The binary file is provided through the workstate variable (currentfile and
 * currentdir properties).
 */
int mysql_dbimpl_process_binary(struct workstate * ws) {
  char buffer[SQLLINESIZE];
  MYSQL_RES * result;
  MYSQL_ROW row;
  int num_fields;

  strcpy(buffer, "select v.filename as filename, v.filetype as filetype, v.filematch as filematch, v.contentmatch as contentmatch, c.cpepart as cpepart, c.cpevendor as cpevendor, c.cpeproduct as cpeproduct, c.cpeversion as cpeversion, c.cpeupdate as cpeupdate, c.cpeedition as cpeedition, c.cpelanguage as cpelanguage c.cpeswedition as cpeswedition, c.cpetargetsw as cpetargetsw, c.cpetargethw as cpetargethw, c.cpeother as cpeother from tb_versionmatch v, tb_cpe c where v.cpe = c.cpeid and \"");
  strcat(buffer, ws->currentfile);
  strcat(buffer,"\" between filename and filename || \"z\";");

  MYSQL_QUERY(ws->conn, buffer)
  result = mysql_store_result(ws->conn);
  num_fields = mysql_num_fields(result);
  
  while ((row = mysql_fetch_row(result))) {
    int rc;
    regex_t preg;
    regmatch_t pmatch[16]; // Assuming the maximum amount of detected groups is 16
    struct cpe_data cpe_data;
    int filetype = 0;

    sprintf(buffer, "cpe:/%s:%s:%s:%s:%s:%s:%s", row[4], row[5], row[6], row[7], row[8], row[9], row[10]);
    string_to_cpe(&cpe_data, buffer);

    rc = regcomp(&preg, row[2], REG_EXTENDED);
    if (rc) {
      fprintf(stderr, "Failed to compile regular expression \"%s\"\n", row[2]);
      return 1;
    };

    rc = regexec(&preg, ws->currentfile, 16, pmatch, 0);
    if (rc) {
      regfree(&preg);
      return 2;
    };

    // Free our memory allocations, and see if the content matches as well.
    regfree(&preg);
    rc = regcomp(&preg, row[3], REG_EXTENDED);
    if (rc) {
      fprintf(stderr, "Failed to compile regular expression \"%s\"\n", row[3]);
      return 3;
    };

    /**
     * Here is where the various version extraction methods are supported.
     * We currently still only support a single method (1, which is the
     * "strings -n 3 <file>" command execution) but now we can see if we can
     * support additional methods as well.
     */
    if (atoi(row[1]) == 1) {
      int ret;
      
      ret = strings_extract_version(ws, &preg, pmatch, &cpe_data);
      if (ret == 0) {
        ret = add_to_mysql_database(ws, cpe_data);
        cpe_to_string(buffer, BUFFERSIZE, cpe_data);
	update_binmatch_files(ws, ret);
        fprintf(stdout, " - Found match for %s/%s:\t%s\n", ws->currentdir, ws->currentfile, buffer);
      };
    } else {
      fprintf(stderr, " ! %s/%s: The mysql implementation currently doesn't support file type %d\n", ws->currentdir, ws->currentfile, filetype);
    };
    return 0;
  };
};

int mysql_dbimpl_verify_installed_versus_cve(struct workstate * ws) {
  char stmt[SQLLINESIZE*8];
  MYSQL_RES * result;
  MYSQL_ROW row;

  // First run a full-match test
  sprintf(stmt, "SELECT a.basedir AS basedir, a.filename AS filename, b.year AS year, b.sequence AS sequence, b.cvss AS cvss, c.cpepart AS cpepart, c.cpevendor AS cpevendor, c.cpeproduct AS cpeproduct, c.cpeversion AS cpeversion, c.cpeupdate AS cpeupdate, c.cpeedition AS cpeedition, c.cpelanguage AS cpelanguage, c.cpeswedition AS cpeswedition, c.cpetargetsw AS cpetargetsw, c.cpetargethw AS cpetargethw, c.cpeother AS cpeother FROM tb_binmatch a, tb_cve b, tb_cpe c WHERE (a.cpe = b.cpe) AND (a.cpe = c.cpeid) AND (a.hostname = \"%s\") AND (a.userdefkey = \"%s\")", ws->hostname, ws->userdefkey);
  MYSQL_QUERY(ws->conn, stmt)
  result = mysql_store_result(ws->conn);
  while (row = mysql_fetch_row(result)) {
    struct cpe_data cpedata;
    char filename[FILENAMESIZE*2+1];
    int year = 0;
    int sequence = 0;
    int cvssScore = 0;

    sprintf(filename, "%s/%s", row[0], row[1]);
    year = atoi(row[2]);
    sequence = atoi(row[3]);
    cvssScore = atoi(row[4]);
    cpedata.part = row[5][0];
    strncpy(cpedata.vendor, row[6], FIELDSIZE);
    strncpy(cpedata.product, row[7], FIELDSIZE);
    strncpy(cpedata.version, row[8], FIELDSIZE);
    strncpy(cpedata.update, row[9], FIELDSIZE);
    strncpy(cpedata.edition, row[10], FIELDSIZE);
    strncpy(cpedata.language, row[11], FIELDSIZE);
    strncpy(cpedata.swedition, row[12], FIELDSIZE);
    strncpy(cpedata.targetsw, row[13], FIELDSIZE);
    strncpy(cpedata.targethw, row[14], FIELDSIZE);
    strncpy(cpedata.other, row[15], FIELDSIZE);
  
    show_potential_vulnerabilities(ws, year, sequence, cvssScore, filename, cpedata, 0);
  }
  mysql_free_result(result);
  // Now, we do the same test, but for those hits where update/edition/language isn't set/detected
  sprintf(stmt, "SELECT a.basedir AS basedir, a.filename AS filename, b.year AS year, b.sequence AS sequence, b.cvss AS cvss, c.cpepart AS cpepart, c.cpevendor AS cpevendor, c.cpeproduct AS cpeproduct, c.cpeversion AS cpeversion, c.cpeupdate AS cpeupdate, c.cpeedition AS cpeedition, c.cpelanguage AS cpelanguage, c.cpeswedition AS cpeswedition, c.cpetargetsw AS cpetargetsw, c.cpetargethw AS cpetargethw, c.cpeother AS cpeother FROM tb_binmatch a, tb_cve b, tb_cpe c, tb_cpe_parents d WHERE (a.cpe = d.childcpe) AND (b.cpe = d.childcpe) AND (c.cpeid = d.mastercpe) AND (a.hostname = \"%s\") AND (a.userdefkey = \"%s\")", ws->hostname, ws->userdefkey);
  MYSQL_QUERY(ws->conn, stmt)
  result = mysql_store_result(ws->conn);
  while (row = mysql_fetch_row(result)) {
    struct cpe_data cpedata;
    char filename[FILENAMESIZE*2+1];
    int year = 0;
    int sequence = 0;
    int cvssScore = 0;

    sprintf(filename, "%s/%s", row[0], row[1]);
    year = atoi(row[2]);
    sequence = atoi(row[3]);
    cvssScore = atoi(row[4]);
    cpedata.part = row[6][0];
    strncpy(cpedata.vendor, row[6], FIELDSIZE);
    strncpy(cpedata.product, row[7], FIELDSIZE);
    strncpy(cpedata.version, row[8], FIELDSIZE);
    strncpy(cpedata.update, row[9], FIELDSIZE);
    strncpy(cpedata.edition, row[10], FIELDSIZE);
    strncpy(cpedata.language, row[11], FIELDSIZE);
    strncpy(cpedata.swedition, row[12], FIELDSIZE);
    strncpy(cpedata.targetsw, row[13], FIELDSIZE);
    strncpy(cpedata.targethw, row[14], FIELDSIZE);
    strncpy(cpedata.other, row[15], FIELDSIZE);
  
    show_potential_vulnerabilities(ws, year, sequence, cvssScore, filename, cpedata, 1);
  }
  mysql_free_result(result);

  if (ws->arg->reporthigher != 0) {
    sprintf(stmt, "SELECT DISTINCT a.basedir AS basedir, a.filename AS filename, b.year AS year, b.sequence AS sequence, b.cvss AS cvss, c2.cpepart AS cpepart, c2.cpevendor AS cpevendor, c2.cpeproduct AS cpeproduct, c2.cpeversion AS cpeversion, c2.cpeupdate AS cpeupdate, c2.cpeedition AS cpeedition, c2.cpelanguage AS cpelanguage, c2.cpeswedition AS cpeswedition, c2.cpetargetsw AS cpetargetsw, c2.cpetargethw AS cpetargethw, c2.cpeother AS cpeother FROM tb_binmatch a, tb_cve b, tb_cpe c, tb_cpe c2, tb_cpe_versions e, tb_cpe_versions e2 WHERE (a.cpe = c2.cpeid) AND (c2.cpeversion = e2.cpeversion) AND (b.cpe = c.cpeid) AND (c.cpeversion = e.cpeversion) AND (a.hostname = \"%s\") AND (a.userdefkey = \"%s\") AND "
    "(c.cpevendor = c2.cpevendor) and "
    "(c.cpeproduct = c2.cpeproduct) and "
    "("
    "  ("
    "    (e.f1 > e2.f1) or "
    "    ("
    "      (e.f1 = e2.f1) and "
    "      (e.f2 > e2.f2)"
    "    ) or "
    "    ("
    "      (e.f1 = e2.f1) and "
    "      (e.f2 = e2.f2) and "
    "      (e.f3 > e2.f3)"
    "    ) or "
    "    ("
    "      (e.f1 = e2.f1) and "
    "      (e.f2 = e2.f2) and "
    "      (e.f3 = e2.f3) and "
    "      (e.f4 > e2.f4)"
    "    ) or "
    "    ("
    "      (e.f1 = e2.f1) and "
    "      (e.f2 = e2.f2) and "
    "      (e.f3 = e2.f3) and "
    "      (e.f4 = e2.f4) and "
    "      (e.f5 > e2.f5)"
    "    ) or "
    "    ("
    "      (e.f1 = e2.f1) and "
    "      (e.f2 = e2.f2) and "
    "      (e.f3 = e2.f3) and "
    "      (e.f4 = e2.f4) and "
    "      (e.f5 = e2.f5) and "
    "      (e.f6 > e2.f6)"
    "    ) or "
    "    ("
    "      (e.f1 = e2.f1) and "
    "      (e.f2 = e2.f2) and "
    "      (e.f3 = e2.f3) and "
    "      (e.f4 = e2.f4) and "
    "      (e.f5 = e2.f5) and "
    "      (e.f6 = e2.f6) and "
    "      (e.f7 > e2.f7)"
    "    ) or "
    "    ("
    "      (e.f1 = e2.f1) and "
    "      (e.f2 = e2.f2) and "
    "      (e.f3 = e2.f3) and "
    "      (e.f4 = e2.f4) and "
    "      (e.f5 = e2.f5) and "
    "      (e.f6 = e2.f6) and "
    "      (e.f7 = e2.f7) and "
    "      (e.f8 > e2.f8)"
    "    ) or "
    "    ("
    "      (e.f1 = e2.f1) and "
    "      (e.f2 = e2.f2) and "
    "      (e.f3 = e2.f3) and "
    "      (e.f4 = e2.f4) and "
    "      (e.f5 = e2.f5) and "
    "      (e.f6 = e2.f6) and "
    "      (e.f7 = e2.f7) and "
    "      (e.f8 = e2.f8) and "
    "      (e.f9 > e2.f9)"
    "    ) or "
    "    ("
    "      (e.f1 = e2.f1) and "
    "      (e.f2 = e2.f2) and "
    "      (e.f3 = e2.f3) and "
    "      (e.f4 = e2.f4) and "
    "      (e.f5 = e2.f5) and "
    "      (e.f6 = e2.f6) and "
    "      (e.f7 = e2.f7) and "
    "      (e.f8 = e2.f8) and "
    "      (e.f9 = e2.f9) and "
    "      (e.f10 > e2.f10)"
    "    ) or "
    "    ("
    "      (e.f1 = e2.f1) and "
    "      (e.f2 = e2.f2) and "
    "      (e.f3 = e2.f3) and "
    "      (e.f4 = e2.f4) and "
    "      (e.f5 = e2.f5) and "
    "      (e.f6 = e2.f6) and "
    "      (e.f7 = e2.f7) and "
    "      (e.f8 = e2.f8) and "
    "      (e.f9 = e2.f9) and "
    "      (e.f10 = e2.f10) and "
    "      (e.f11 > e2.f11)"
    "    ) or "
    "    ("
    "      (e.f1 = e2.f1) and "
    "      (e.f2 = e2.f2) and "
    "      (e.f3 = e2.f3) and "
    "      (e.f4 = e2.f4) and "
    "      (e.f5 = e2.f5) and "
    "      (e.f6 = e2.f6) and "
    "      (e.f7 = e2.f7) and "
    "      (e.f8 = e2.f8) and "
    "      (e.f9 = e2.f9) and "
    "      (e.f10 = e2.f10) and "
    "      (e.f11 = e2.f11) and "
    "      (e.f12 > e2.f12)"
    "    ) or "
    "    ("
    "      (e.f1 = e2.f1) and "
    "      (e.f2 = e2.f2) and "
    "      (e.f3 = e2.f3) and "
    "      (e.f4 = e2.f4) and "
    "      (e.f5 = e2.f5) and "
    "      (e.f6 = e2.f6) and "
    "      (e.f7 = e2.f7) and "
    "      (e.f8 = e2.f8) and "
    "      (e.f9 = e2.f9) and "
    "      (e.f10 = e2.f10) and "
    "      (e.f11 = e2.f11) and "
    "      (e.f12 = e2.f12) and "
    "      (e.f13 > e2.f13)"
    "    ) or "
    "    ("
    "      (e.f1 = e2.f1) and "
    "      (e.f2 = e2.f2) and "
    "      (e.f3 = e2.f3) and "
    "      (e.f4 = e2.f4) and "
    "      (e.f5 = e2.f5) and "
    "      (e.f6 = e2.f6) and "
    "      (e.f7 = e2.f7) and "
    "      (e.f8 = e2.f8) and "
    "      (e.f9 = e2.f9) and "
    "      (e.f10 = e2.f10) and "
    "      (e.f11 = e2.f11) and "
    "      (e.f12 = e2.f12) and "
    "      (e.f13 = e2.f13) and "
    "      (e.f14 > e2.f14)"
    "    ) or "
    "    ("
    "      (e.f1 = e2.f1) and "
    "      (e.f2 = e2.f2) and "
    "      (e.f3 = e2.f3) and "
    "      (e.f4 = e2.f4) and "
    "      (e.f5 = e2.f5) and "
    "      (e.f6 = e2.f6) and "
    "      (e.f7 = e2.f7) and "
    "      (e.f8 = e2.f8) and "
    "      (e.f9 = e2.f9) and "
    "      (e.f10 = e2.f10) and "
    "      (e.f11 = e2.f11) and "
    "      (e.f12 = e2.f12) and "
    "      (e.f13 = e2.f13) and "
    "      (e.f14 = e2.f14) and "
    "      (e.f15 > e2.f15)"
 /*
    "    ) or "
    "    ("
    "      (e.f1 = e2.f1) and "
    "      (e.f2 = e2.f2) and "
    "      (e.f3 = e2.f3) and "
    "      (e.f4 = e2.f4) and "
    "      (e.f5 = e2.f5) and "
    "      (e.f6 = e2.f6) and "
    "      (e.f7 = e2.f7) and "
    "      (e.f8 = e2.f8) and "
    "      (e.f9 = e2.f9) and "
    "      (e.f10 = e2.f10) and "
    "      (e.f11 = e2.f11) and "
    "      (e.f12 = e2.f12) and "
    "      (e.f13 = e2.f13) and "
    "      (e.f14 = e2.f14) and "
    "      (e.f15 = e2.f15)" 
    "    )" 

    If I bring this back, the next "   )" needs to be removed
*/
    "    )"
    "  )"
    ") and "
    "( "
    "  (c.cpeedition = c2.cpeedition) or "
    "  ( "
    "    (c.cpeedition <> 1 ) and "
    "        (c2.cpeedition = 0) "
    "  ) "
    ") and "
    "( "
    "  (c.cpeupdate = c2.cpeupdate) or "
    "  ( "
    "    (c.cpeupdate <> 0 ) and "
    "    (c2.cpeupdate = 0 ) "
    "  ) "
    ") and "
    "( "
    "  (c.cpelanguage = c2.cpelanguage) or "
    "  ( "
    "    (c.cpelanguage <> 0) and "
    "    (c2.cpelanguage = 0 ) "
    "  ) "
    ") and "
    "( "
    "  (c.cpeswedition = c2.cpeswedition) or "
    "  ( "
    "    (c.cpeswedition <> 0 ) and "
    "    (c2.cpeswedition = 0 ) "
    "  ) "
    ") and "
    "( "
    "  (c.cpetargetsw = c2.cpetargetsw) or "
    "  ( "
    "    (c.cpetargetsw <> 0) and "
    "    (c2.cpetargetsw = 0 ) "
    "  ) "
    ") and "
    "( "
    "  (c.cpetargethw = c2.cpetargethw) or "
    "  ( "
    "    (c.cpetargethw <> 0) and "
    "    (c2.cpetargethw = 0 ) "
    "  ) "
    ") and "
    "( "
    "  (c.cpeother = c2.cpeother) or "
    "  ( "
    "    (c.cpeother <> 0) and "
    "    (c2.cpeother = 0 ) "
    "  ) "
    ")", ws->hostname, ws->userdefkey);
    MYSQL_QUERY(ws->conn, stmt)
    result = mysql_store_result(ws->conn);
    while (row = mysql_fetch_row(result)) {
      struct cpe_data cpedata;
      char filename[FILENAMESIZE*2+1];
      int year = 0;
      int sequence = 0;
      int cvssScore = 0;

      sprintf(filename, "%s/%s", row[0], row[1]);
      year = atoi(row[2]);
      sequence = atoi(row[3]);
      cvssScore = atoi(row[4]);
      cpedata.part = row[5][0];
      strncpy(cpedata.vendor, row[6], FIELDSIZE);
      strncpy(cpedata.product, row[7], FIELDSIZE);
      strncpy(cpedata.version, row[8], FIELDSIZE);
      strncpy(cpedata.update, row[9], FIELDSIZE);
      strncpy(cpedata.edition, row[10], FIELDSIZE);
      strncpy(cpedata.language, row[11], FIELDSIZE);
      strncpy(cpedata.swedition, row[12], FIELDSIZE);
      strncpy(cpedata.targetsw, row[13], FIELDSIZE);
      strncpy(cpedata.targethw, row[14], FIELDSIZE);
      strncpy(cpedata.other, row[15], FIELDSIZE);
   
      show_potential_vulnerabilities(ws, year, sequence, cvssScore, filename, cpedata, 2);
    }
    mysql_free_result(result);
  }
};

int mysql_dbimpl_initialize_workstate(struct workstate * ws) {
  char * hostname;
  char * userkey;

  ws->conn = mysql_init(NULL);

  if (ws->conn == NULL) {
    fprintf(stderr, "Error %u: %s\n", mysql_errno(ws->conn), mysql_error(ws->conn));
    return 1;
  }

  hostname = (char *) calloc(FIELDSIZE, sizeof(char));
  userkey  = (char *) calloc(FIELDSIZE, sizeof(char));
  // Make sure that hostname and userdefined key cannot be abused
  
  mysql_real_escape_string(ws->conn, hostname, ws->hostname, swstrlen(ws->hostname));
  mysql_real_escape_string(ws->conn, userkey, ws->userdefkey, swstrlen(ws->userdefkey));

  free(ws->hostname);
  ws->hostname = hostname;

  free(ws->userdefkey);
  ws->userdefkey = userkey;
  
  return 0;
};

/**
 * Add versiongather entry into the database
 */
int mysql_dbimpl_add_versiongather(struct workstate * ws, struct versiongather_data vg, struct cpe_data cpe) {
  char stmt[SQLLINESIZE];
  char filematch[FIELDSIZE];
  char expression[FIELDSIZE];
  int cpid = 0;

  cpid = add_to_mysql_database(ws, cpe);

  mysql_real_escape_string(ws->conn, filematch, vg.filematch, swstrlen(vg.filematch));
  mysql_real_escape_string(ws->conn, expression, vg.versionexpression, swstrlen(vg.versionexpression));

  sprintf(stmt, "insert into tb_versionmatch values (\"%s\", %d, \"%s\", \"%s\", %d);", vg.filepart, vg.gathertype, filematch, expression, cpid);
  if (mysql_query(ws->conn, stmt)) {
    fprintf(stderr, "Error %u: %s\n", mysql_errno(ws->conn), mysql_error(ws->conn));
    return 1;
  };

  return 0;
};

/**
 * Initialize the databases
 */
int mysql_dbimpl_initialize_databases(struct workstate * ws) {
  char buffer[SQLLINESIZE];
  
  MYSQL_QUERY(ws->conn, "DROP TABLE IF EXISTS tb_binmatch")
  MYSQL_QUERY(ws->conn, "DROP TABLE IF EXISTS tb_cpe_versions")
  MYSQL_QUERY(ws->conn, "DROP TABLE IF EXISTS tb_cve")
  MYSQL_QUERY(ws->conn, "DROP TABLE IF EXISTS tb_cpe_parents")
  MYSQL_QUERY(ws->conn, "DROP TABLE IF EXISTS tb_versionmatch")
  MYSQL_QUERY(ws->conn, "DROP TABLE IF EXISTS tb_cpe")
  sprintf(buffer, "CREATE TABLE tb_cpe (cpeid INTEGER PRIMARY KEY NOT NULL AUTO_INCREMENT, cpepart CHAR(1), cpevendor VARCHAR(%d), cpeproduct VARCHAR(%d), cpeversion VARCHAR(%d), cpeupdate VARCHAR(%d), cpeedition VARCHAR(%d), cpelanguage VARCHAR(%d), cpeswedition VARCHAR(%d), cpetargetsw VARCHAR(%d), cpetargethw VARCHAR(%d), cpeother VARCHAR(%d)) ENGINE=InnoDB", FIELDSIZE, FIELDSIZE, FIELDSIZE, FIELDSIZE, FIELDSIZE, FIELDSIZE, FIELDSIZE, FIELDSIZE, FIELDSIZE, FIELDSIZE);
  MYSQL_QUERY(ws->conn, buffer)
  MYSQL_QUERY(ws->conn, "CREATE INDEX cpeidx ON tb_cpe (cpevendor, cpeproduct)")

  sprintf(buffer, "CREATE TABLE tb_versionmatch (filename VARCHAR(%d), filetype SMALLINT, filematch VARCHAR(%d), contentmatch VARCHAR(%d), cpe INT, FOREIGN KEY (cpe) REFERENCES tb_cpe(cpeid) ON DELETE CASCADE) ENGINE=InnoDB", FILENAMESIZE, FILENAMESIZE, LARGEFIELDSIZE);
  MYSQL_QUERY(ws->conn, buffer)
  MYSQL_QUERY(ws->conn, "CREATE INDEX vmidx ON tb_versionmatch (filename)")

  sprintf(buffer, "CREATE TABLE tb_binmatch (basedir VARCHAR(%d), filename VARCHAR(%d), cpe INT, fullmatch INT, hostname VARCHAR(%d), userdefkey VARCHAR(256), FOREIGN KEY (cpe) REFERENCES tb_cpe(cpeid) ON DELETE CASCADE) ENGINE=InnoDB", FILENAMESIZE, FILENAMESIZE, FIELDSIZE);
  MYSQL_QUERY(ws->conn, buffer)
  MYSQL_QUERY(ws->conn, "CREATE TABLE tb_cve (year SMALLINT, sequence INT, cpe INT, cvss INT, FOREIGN KEY (cpe) REFERENCES tb_cpe(cpeid) ON DELETE CASCADE) ENGINE=InnoDB")
  MYSQL_QUERY(ws->conn, "CREATE INDEX cveidx ON tb_cve (year, sequence)")
  MYSQL_QUERY(ws->conn, "CREATE INDEX cveidx2 ON tb_cve (cpe)")
  MYSQL_QUERY(ws->conn, "CREATE INDEX binmatchidx ON tb_binmatch (cpe)")
  MYSQL_QUERY(ws->conn, "CREATE INDEX hostnameidx ON tb_binmatch (hostname)")
  MYSQL_QUERY(ws->conn, "CREATE INDEX userdefkeyidx ON tb_binmatch (userdefkey)")

  sprintf(buffer, "CREATE TABLE tb_cpe_versions (cpeversion varchar(255) primary key, f1 integer, f2 integer, f3 integer, f4 integer, f5 integer, f6 integer, f7 integer, f8 integer, f9 integer, f10 integer, f11 integer, f12 integer, f13 integer, f14 integer, f15 integer)");
  MYSQL_QUERY(ws->conn, buffer)
  MYSQL_QUERY(ws->conn, "CREATE INDEX cpe_versions_idx on tb_cpe_versions (cpeversion)")
  MYSQL_QUERY(ws->conn, "CREATE INDEX cpe_versions_2_idx on tb_cpe_versions (f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, f14, f15)")
  
  MYSQL_QUERY(ws->conn, "CREATE TABLE tb_cpe_parents (mastercpe int, childcpe int, FOREIGN KEY (mastercpe) REFERENCES tb_cpe(cpeid) ON DELETE CASCADE, FOREIGN KEY (childcpe) REFERENCES tb_cpe(cpeid) ON DELETE CASCADE) ENGINE=InnoDB")
};

/**
 * Report on detected software/versions
 */
int mysql_dbimpl_report_installed(struct workstate * ws, int showfiles) {
  char stmt[SQLLINESIZE];
  MYSQL_RES * result;
  MYSQL_ROW row;

  sprintf(stmt, "SELECT DISTINCT a.cpe AS cpe, b.cpepart AS cpepart, b.cpevendor AS cpevendor, b.cpeproduct AS cpeproduct, b.cpeversion AS cpeversion, b.cpeupdate AS cpeupdate, b.cpeedition AS cpeedition, b.cpelanguage AS cpelanguage, b.cpeswedition AS cpeswedition, b.cpetargetsw AS cpetargetsw, b.cpetargethw AS cpetargethw, b.cpeother AS cpeother FROM tb_binmatch a, tb_cpe b WHERE b.cpeid = a.cpe AND a.hostname = \"%s\" AND a.userdefkey = \"%s\"", ws->hostname, ws->userdefkey);
  MYSQL_QUERY(ws->conn, stmt)
  result = mysql_store_result(ws->conn);
  row = mysql_fetch_row(result);
  while (row) {
    int cpe;
    struct cpe_data cpedata;

    cpe = atoi(row[0]);
    cpedata.part = row[1][0];
    strncpy(cpedata.vendor, row[2], FIELDSIZE);
    strncpy(cpedata.product, row[3], FIELDSIZE);
    strncpy(cpedata.version, row[4], FIELDSIZE);
    strncpy(cpedata.update, row[5], FIELDSIZE);
    strncpy(cpedata.edition, row[6], FIELDSIZE);
    strncpy(cpedata.language, row[7], FIELDSIZE);
    strncpy(cpedata.swedition, row[8], FIELDSIZE);
    strncpy(cpedata.targetsw, row[9], FIELDSIZE);
    strncpy(cpedata.targethw, row[10], FIELDSIZE);
    strncpy(cpedata.other, row[11], FIELDSIZE);

    if (showfiles) {
      MYSQL_RES * result2;
      MYSQL_ROW row2;
      int numfiles = 0;
      int i;

      zero_string(stmt, SQLLINESIZE);
      sprintf(stmt, "SELECT count(*) FROM tb_binmatch WHERE cpe = %d AND hostname = \"%s\" AND userdefkey = \"%s\"", cpe, ws->hostname, ws->userdefkey);
      MYSQL_QUERY(ws->conn, stmt)
      result2 = mysql_store_result(ws->conn);
      row2 = mysql_fetch_row(result2);
      numfiles = atoi(row2[0]);
      mysql_free_result(result2);
      ws->resultlist = (void **) calloc(numfiles, sizeof(char *));
      ws->numresults = numfiles;

      sprintf(stmt, "SELECT basedir, filename FROM tb_binmatch WHERE cpe = %d AND hostname = \"%s\" AND userdefkey = \"%s\"", cpe, ws->hostname, ws->userdefkey);
      MYSQL_QUERY(ws->conn, stmt)
      result2 = mysql_store_result(ws->conn);
      row2 = mysql_fetch_row(result2);
      i = 0;
      while (row2) {
        char * fullfilename = (char *) calloc(FIELDSIZE*2+1, sizeof(char));
	sprintf(fullfilename, "%s/%s", row2[0], row2[1]);
	ws->resultlist[i] = fullfilename;

	i++;
	row2 = mysql_fetch_row(result2);
      };
      mysql_free_result(result2);
      show_installed_software(ws, cpedata.vendor, cpedata.product, cpedata.version, cpedata.update, cpedata.edition, cpedata.language, cpedata.swedition, cpedata.targetsw, cpedata.targethw, cpedata.other, ws->numresults, (const char **) ws->resultlist);
      clear_resultlist(ws);
      free(ws->resultlist);
    } else {
      show_installed_software(ws, cpedata.vendor, cpedata.product, cpedata.version, cpedata.update, cpedata.edition, cpedata.language, cpedata.swedition, cpedata.targetsw, cpedata.targethw, cpedata.other, ws->numresults, (const char **) ws->resultlist);
    };
    row = mysql_fetch_row(result);
  };
  mysql_free_result(result);
  return 0;
};

int check_cvecpe_in_mysql_db(struct workstate * ws, int year, int sequence, struct cpe_data cpe) {
  int rc = 0;
  char stmt[SQLLINESIZE];
  MYSQL_RES * result;
  MYSQL_ROW row;

  rc = add_to_mysql_database(ws, cpe);
 
  sprintf(stmt, "select count(*) from tb_cve where year = %d and sequence = %d and cpe = %d;", year, sequence, rc);
  MYSQL_QUERY(ws->conn, stmt)
  result = mysql_store_result(ws->conn);
  row = mysql_fetch_row(result);
  rc = atoi(row[0]);
  mysql_free_result(result);
  return rc;
};

/**
 * Initialization for storing CVE data in the database.
 *
 * The initialization function is meant to allow implementations
 * to optimize their functions (like starting a transaction scope).
 */
int mysql_dbimpl_store_cve_in_db_init(struct workstate * ws) {
  MYSQL_QUERY(ws->conn, "START TRANSACTION")

  return 0;
};


/**
 * Store the passed CVE entry in the database
 */
int mysql_dbimpl_store_cve_in_db(struct workstate * ws, char * cveId, char * cpeId, char * cvssNum) {
  int rc = 0;
  char stmt[SQLLINESIZE];
  int year, sequence, cvssScore;
  struct cpe_data cpe;
  MYSQL_RES * result;
  MYSQL_ROW row;

  rc = cve_to_vars(&year, &sequence, cveId);
  if (rc == 1) {
    return 1;
  };
  string_to_cpe(&cpe, cpeId);

  ws->rc = 0;
  rc = check_cvecpe_in_mysql_db(ws, year, sequence, cpe);
  // if ((rc != 0) && (ws->rc != 0)) {
  if (rc != 0) {
    return 1;
  };

  cvssScore = atoi(cvssNum);
  cvssScore = cvssScore * 10 + atoi(strchr(cvssNum, '.')+1);

  sprintf(stmt, "select cpeid from tb_cpe where cpepart = \"%c\" and cpevendor = \"%s\" and cpeproduct = \"%s\" and cpeversion = \"%s\" and cpeupdate = \"%s\" and cpeedition = \"%s\" and cpelanguage = \"%s\" and cpeswedition = \"%s\" and cpetargetsw = \"%s\" and cpetargethw = \"%s\" and cpeother = \"%s\";",  cpe.part, cpe.vendor, cpe.product, cpe.version, cpe.update, cpe.edition, cpe.language, cpe.swedition, cpe.targetsw, cpe.targethw, cpe.other);
  MYSQL_QUERY(ws->conn, stmt)
  result = mysql_store_result(ws->conn);
  row = mysql_fetch_row(result);
  rc = atoi(row[0]);
  mysql_free_result(result);

  sprintf(stmt, "insert into tb_cve values (%d, %d, %d, %d);", year, sequence, rc, cvssScore);
  MYSQL_QUERY(ws->conn, stmt)
  return 0;
}

/**
 * Exit method for finalizing the storage of CVE data in the database.
 *
 * The exit method is meant to allow implementations to optimize their functions
 * (like committing at the transaction scope).
 */
int mysql_dbimpl_store_cve_in_db_exit(struct workstate * ws) {
  MYSQL_QUERY(ws->conn, "COMMIT")
 
  return 0;
};

/**
 * Checkpoint method for the CVE upload process.
 *
 * The checkpoint method allows for intermediate COMMIT statements. We currently
 * do a COMMIT and START TRANSACTION again, but this could in the future be
 * configured (say using mysql.checkpoint = 4 --> each 400 entries)?
 */
int mysql_dbimpl_store_cve_in_db_checkpoint(struct workstate * ws) {
  MYSQL_QUERY(ws->conn, "COMMIT")
  MYSQL_QUERY(ws->conn, "START TRANSACTION")

  return 0;
};

/**
 * Initialize arguments structure with database-specific fields
 */
int mysql_dbimpl_initialize_arguments(struct arguments * arg) {
	return 0;
};

/**
 * Check if mysql support is built in
 */
int mysql_dbimpl_supported() {
	return 1;
};
