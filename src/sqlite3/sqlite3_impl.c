#include "sqlite3_impl.h"

/*
 * Copyright 2010 Sven Vermeulen.
 * Subject to the GNU Public License, version 3.
 */
 
/***********************************************************************************************
 * Helper functions for the sqlite3 database manipulations
 ***********************************************************************************************/
const char partchar[] = { 'a', 'h', 'o' };

/**
 * Due to sizing issues, we need to use multiple databases for this
 * application. To easily keep track of the databases, a helper function
 * like this one allows us to quickly find the correct sqlite3 database.
 */
sqlite3 * get_local_db(struct workstate * ws, char part, int len) {
        if (part == 'a') {
                return ws->localdb[len];
        } else if (part == 'h') {
                return ws->localdb[FIELDSIZE+len];
        } else if (part == 'o') {
                return ws->localdb[2*FIELDSIZE+len];
        };

        return NULL;
};

int get_cpe_dataresult(void * cbobj, int argc, char **argv, char **azColName) {
        int i = 0;
        struct workstate * ws = (struct workstate *) cbobj;

        for(i = 0; i < argc; i++) {
                if (strcmp(azColName[i], "cpepart") == 0) {
                        ws->cpebuffer.part = argv[i][0];
                        continue;
                }
                if (strcmp(azColName[i], "cpevendor") == 0) {
                        strncpy(ws->cpebuffer.vendor, argv[i], FIELDSIZE);
                        continue;
                }
                if (strcmp(azColName[i], "cpeproduct") == 0) {
                        strncpy(ws->cpebuffer.product, argv[i], FIELDSIZE);
                        continue;
                }
                if (strcmp(azColName[i], "cpeversion") == 0) {
                        strncpy(ws->cpebuffer.version, argv[i], FIELDSIZE);
                        continue;
                }
                if (strcmp(azColName[i], "cpeupdate") == 0) {
                        strncpy(ws->cpebuffer.update, argv[i], FIELDSIZE);
                        continue;
                }
                if (strcmp(azColName[i], "cpeedition") == 0) {
                        strncpy(ws->cpebuffer.edition, argv[i], FIELDSIZE);
                        continue;
                }
                if (strcmp(azColName[i], "cpelanguage") == 0) {
                        strncpy(ws->cpebuffer.language, argv[i], FIELDSIZE);
                        continue;
                };
        };

        ws->rc = 0;
        return 0;
};

int get_filelist(void * cbobj, int argc, char **argv, char **azColName) {
        int i = 0;
        struct workstate * ws = (struct workstate *) cbobj;
        int current = ws->rc;
        char basedir[FILENAMESIZE];
        char filename[FILENAMESIZE];
        char * fullfilename;

        for (i = 0; i < argc; i++) {
                if (strcmp(azColName[i], "basedir") == 0) {
                        strncpy(basedir, argv[i], FILENAMESIZE);
                        continue;
                }
                if (strcmp(azColName[i], "filename") == 0) {
                        strncpy(filename, argv[i], FILENAMESIZE);
                        continue;
                };
        };

        fullfilename = (char *) calloc(FILENAMESIZE*2+1, sizeof(char));
        sprintf(fullfilename, "%s/%s", basedir, filename);
        ws->resultlist[current] = fullfilename;
        ws->rc = current+1;

        return 0;
};

int get_cpe_data(sqlite3 * db, char * stmt, struct workstate * ws) {
        int rc = 0;
        char * errmsg;

        ws->rc = 0;
	EXEC_SQLITE(rc, db, stmt, get_cpe_dataresult)

        return ws->rc;
};

/**
 * get_int_value - Return a simple integer result
 */
int get_int_value(sqlite3 * db, char * stmt, struct workstate * ws) {
  int rc = 0;
  int retval = 0;
  sqlite3_stmt * intstmt;

  PREPARE_SQLITE(rc, db, stmt, intstmt);
  while ((rc = sqlite3_step(intstmt)) == SQLITE_ROW) {
    retval = sqlite3_column_int(intstmt, 0);
  };
  ASSERT_FINALIZE(rc, stmt, intstmt);

  return retval;
};

int get_cpelist(void * cbobj, int argc, char **argv, char **azColName) {
        int i = 0;
        struct workstate * ws = (struct workstate *) cbobj;
        char part = '\0';
        char stmt[SQLLINESIZE];
        int length = 0;
        int cpeid = 0;
        int showfiles = ws->rc;
        struct cpe_data cpedata;
        char * errmsg;

        if (argc != 3)
                return 1;

        for (i = 0; i < argc; i++) {
                if (strcmp(azColName[i], "cpepart") == 0) {
                        part = argv[i][0];
                        continue;
                }
                if (strcmp(azColName[i], "cpevendorlength") == 0) {
                        length = atoi(argv[i]);
                        continue;
                }
                // This one must be at the end, 'cause it always matches the previous hits as well
                if (strcmp(azColName[i], "cpe") == 0) {
                        cpeid = atoi(argv[i]);
                        continue;
                }
        };
        
        zero_string(stmt, SQLLINESIZE);
        sprintf(stmt, "select cpepart, cpevendor, cpeproduct, cpeversion, cpeupdate, cpeedition, cpelanguage from tb_cpe_%c_%d where cpeid = %d;", part, length, cpeid);
        i = get_cpe_data(get_local_db(ws, part, length), stmt, ws);
        if (i != 0)
                return i;
        cpedata = ws->cpebuffer;
        ws->numresults = 0;
        if (showfiles) {
                // Step 1 - Get number of hits
                zero_string(stmt, SQLLINESIZE);
                sprintf(stmt, "SELECT count(rowid) FROM tb_binmatch WHERE cpepart = \'%c\' AND cpevendorlength = %d AND cpe = %d;", part, length, cpeid);
                i = get_int_value(ws->localdb[0], stmt, ws);
                ws->resultlist = (void **) calloc(i, sizeof(char *));
                ws->numresults = i;
                ws->rc = 0;
                // Step 2 - Get list of files
                zero_string(stmt, SQLLINESIZE);
                sprintf(stmt, "SELECT basedir, filename FROM tb_binmatch WHERE cpepart = \'%c\' AND cpevendorlength = %d AND cpe = %d;", part, length, cpeid);
		EXEC_SQLITE_RETURNFAIL(i, ws->localdb[0], stmt, get_filelist)
        };
        show_installed_software(ws, cpedata.vendor, cpedata.product, cpedata.version, cpedata.update, cpedata.edition, cpedata.language, ws->numresults, (const char **) ws->resultlist);

        if (showfiles) {
                clear_resultlist(ws);
                free(ws->resultlist);
        };

        return i;
};


int run_statement(struct workstate * ws, sqlite3 * db, char * stmt) {
  int rc = 0;
  char * errmsg;

  EXEC_SQLITE(rc, db, stmt, NULL)

  return rc;
};

int run_statement_alldb(struct workstate * ws, char * stmt) {
  int i = 0;
  int rc;

  for (i = 0; i < 3*FIELDSIZE+1; i++) {
    rc = run_statement(ws, ws->localdb[i], stmt);
    if (rc)
    	break;
  };

  return rc;
};

/*
 * feed_cpe_versions_table - Enrich the tb_cpe_versions table with the expanded
 * version information.
 */
int feed_cpe_versions_table(struct workstate * ws, char type, int length) {
  char stmt[SQLLINESIZE];
  sqlite3_stmt * versstmt;
  int rc = 0;

  zero_string(stmt, SQLLINESIZE);

  // for each version in the tb_cpe_* table...
  sprintf(stmt, "SELECT distinct cpeversion from tb_cpe_%c_%d;", type, length);
  PREPARE_SQLITE(rc, get_local_db(ws, type, length), stmt, versstmt)
  while ((rc = sqlite3_step(versstmt)) == SQLITE_ROW) {
    const unsigned char * cpeversion;
    int d;
    int f[15];

    cpeversion = sqlite3_column_text(versstmt, 0); // get the version (string)

    for (d = 0; d < 15; d++)
      f[d] = get_version_field((char *) cpeversion, d); // get the next version part (from the string)

      // ... add the expanded version into the tb_cpe_versions table
      zero_string(stmt, SQLLINESIZE);
      sprintf(stmt, "INSERT OR REPLACE INTO tb_cpe_versions (cpeversion, f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, f14, f15) values (\"%s\", %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d);", cpeversion, f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[9], f[10], f[11], f[12], f[13], f[14]);
      rc = run_statement(ws, get_local_db(ws, type, length), stmt);
      if (rc)
        break;
  };
  ASSERT_FINALIZE(rc, stmt, versstmt)

  return rc;
};

/**
 * Clear the version database.
 */
int sqlite_dbimpl_clear_versiondatabase(struct workstate * ws) {
        char stmt[SQLLINESIZE];
	int rc;

        sprintf(stmt, "delete from tb_binmatch;");

        rc = run_statement(ws, ws->localdb[0], stmt);

	return rc;
};

/**
 * Clear the version gathering data
 */
int sqlite_dbimpl_clear_versiondata(struct workstate * ws) {
        char stmt[SQLLINESIZE];
	int rc;

        sprintf(stmt, "delete from tb_versionmatch;");
        rc = run_statement(ws, ws->matchdb, stmt);

	return rc;
};

/**
 * Run updates on the database (due to cvechecker upgrades or 
 * fixes)
 */
int run_upgrade_fixes(struct workstate * ws) {
  int rc = 0;
  int errState = 0;
  int i;
  int c;
  int numChange = 0;
  char stmt[SQLLINESIZE];
  sqlite3_stmt * sql_stmt;


  /**
   * 1 - Add tables tb_cpe_a_64, tb_cpe_h_64 and tb_cpe_o_64 if they don't exist yet
   *
   * If count(*) returns 0, then there are no tables in the database, so we can create.
   */
  for (c = 0; c < 3; c++) { // cpe part iterator
    for (i = 64; i <= FIELDSIZE; i++) {
      sprintf(stmt, "select count(*) from sqlite_master;");
      rc = get_int_value(get_local_db(ws, partchar[c], i), stmt, ws);
      if (rc == 0) {
        fprintf(stderr, "I am missing the tables in %c%d (tb_cpe_%c_%d). This is to be expected if this is the first run of cvechecker since an upgrade.\nI will now create tb_cpe_%c_%d for you, no further actions are needed.\n", partchar[c], i, partchar[c], i, partchar[c], i);
        zero_string(stmt, SQLLINESIZE);
        sprintf(stmt, "CREATE TABLE tb_cpe_%c_%d (cpeid integer primary key, cpepart char(1), cpevendor char(%d), cpeproduct char(%d), cpeversion char(%d), cpeupdate char(%d), cpeedition char(%d), cpelanguage char(%d));", partchar[c], i, FIELDSIZE, FIELDSIZE, FIELDSIZE, FIELDSIZE, FIELDSIZE, FIELDSIZE);
        rc = run_statement(ws, get_local_db(ws, partchar[c], i), stmt);
	if (rc) {
          fprintf(stderr, "Failed to execute the SQL statement, bailing out...\n");
	  errState = 1;
	  break;
	};
	numChange++;
      };
      rc = 0;
    };
    if (errState)
      break;
  };

  if (errState) {
    return 1;
  };

  /**
   * 2 - Add indexes, performance
   */
  sprintf(stmt, "select count(rowid) from sqlite_master where name = 'binmatchidx';");
  rc = get_int_value(ws->localdb[0], stmt, ws);
  if (rc == 0) {
          fprintf(stderr, "I am missing the index binmatchidx. This is to be expected if this is the first run of cvechecker since an upgrade.\nI will now create binmatchidx for you, no further actions are needed.\n");
          zero_string(stmt, SQLLINESIZE);
          sprintf(stmt, "CREATE INDEX binmatchidx on tb_binmatch (cpe, cpepart, cpevendorlength);");
          rc = run_statement(ws, ws->localdb[0], stmt);
	  if (rc) {
            fprintf(stderr, "Failed to execute SQL statement, bailing out...\n");
	    errState = 1;
	  };
	  numChange++;
  };

  if (errState)
    return 1;

  sprintf(stmt, "select count(rowid) from sqlite_master where name = 'cveidx2';");
  rc = get_int_value(ws->localdb[0], stmt, ws);
  if (rc == 0) {
    fprintf(stderr, "I am missing the index cveidx2. This is to be expected if this is the first run of cvechecker since an upgrade.\nI will now create cveidx2 for you, no further actions are needed.\n");
    zero_string(stmt, SQLLINESIZE);
    sprintf(stmt, "CREATE INDEX cveidx2 on tb_cve (cpe, cpepart, cpevendorlength);");
    rc = run_statement(ws, ws->localdb[0], stmt);
    if (rc) {
      fprintf(stderr, "Failed to execute SQL statement; bailing out...\n");
      errState = 1;
    };
    numChange++;
  };

  if (errState)
    return 1;

  for (i = 1; i <= FIELDSIZE; i++) {
    for (c = 0; c < 3; c++) {
      sprintf(stmt, "select count(rowid) from sqlite_master where name = 'cpe_%c_%d_idx';", partchar[c], i);
      rc = get_int_value(get_local_db(ws, partchar[c], i), stmt, ws);
      if (rc == 0) {
        fprintf(stderr, "I am missing the index cpe_%c_%d_idx. This is to be expected if this is the first run of cvechecker since an upgrade.\nI will now create cpe_%c_%d_idx for you, no further actions are needed.\n", partchar[c], i, partchar[c], i);
        zero_string(stmt, SQLLINESIZE);
        sprintf(stmt, "CREATE INDEX cpe_%c_%d_idx on tb_cpe_%c_%d (cpevendor, cpeproduct, cpeversion, cpeid, cpeedition, cpeupdate, cpelanguage);", partchar[c], i, partchar[c], i);
        rc = run_statement(ws, get_local_db(ws, partchar[c], i), stmt);
	if (rc) {
          fprintf(stderr, "Failing to execute the SQL statement, bailing out...\n");
	  errState = 1;
	  break;
	};
	numChange++;
      };
    };
    if (errState)
      break;
  };

  if (errState)
    return 1;

  /**
   * 3 - Add tb_cpe_version tables and populate 
   */
  for (i = 1; i <= FIELDSIZE; i++) {
    for (c = 0; c < 3; c++) {
      int count1Value = 0;
      int count2Value = 0;

      sprintf(stmt, "select count(rowid) from sqlite_master where name = 'tb_cpe_versions';");
      rc = get_int_value(get_local_db(ws, partchar[c], i), stmt, ws);
      if (rc == 0) {
        fprintf(stderr, "I am missing the tb_cpe_versions table for the database containing tb_cpe_%c_%d. Creating and populating. This is to be expected if you upgraded cvechecker from 1.0 or lower. This action will take a (long) while, be patient.\n", partchar[c], i);
        zero_string(stmt, SQLLINESIZE);

        sprintf(stmt, "CREATE TABLE tb_cpe_versions (cpeversion char(%d) primary key, f1 integer, f2 integer, f3 integer, f4 integer, f5 integer, f6 integer, f7 integer, f8 integer, f9 integer, f10 integer, f11 integer, f12 integer, f13 integer, f14 integer, f15 integer); CREATE INDEX cpe_versions_idx on tb_cpe_versions (cpeversion); CREATE INDEX cpe_versions_2_idx on tb_cpe_versions (f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, f14, f15);", FIELDSIZE);
        rc = run_statement(ws, get_local_db(ws, partchar[c], i), stmt);
	if (rc) {
          fprintf(stderr, "Failed to execute SQL statement, bailing out...\n");
	  errState = 1;
	  break;
	};

        rc = feed_cpe_versions_table(ws, partchar[c], i);
        if (rc) {
          fprintf(stderr, "Failed to execute SQL statement, bailing out...\n");
          errState = 1;
          break;
        };
	numChange++;
      };
      // Check if all versions are persent in tb_cpe_versions
      sprintf(stmt, "select count(distinct cpeversion) from tb_cpe_%c_%d;", partchar[c], i);
      count1Value = get_int_value(get_local_db(ws, partchar[c], i), stmt, ws);
      sprintf(stmt, "select count(distinct cpeversion) from tb_cpe_versions;");
      count2Value = get_int_value(get_local_db(ws, partchar[c], i), stmt, ws);
      if (count1Value != count2Value) {
        // Not all versions are mentioned in tb_cpe_versions, this would break
	// the ability of cvechecker to report on higher versions (bug #7).
	//
	// First purge the table
	sprintf(stmt, "DELETE FROM tb_cpe_versions;");
	rc = run_statement(ws, get_local_db(ws, partchar[c], i), stmt);
	if (rc) {
          fprintf(stderr, "Failed to purge tb_cpe_versions table.\n");
	  errState = 1;
	  break;
	};
        // Now feed it back in
	rc = feed_cpe_versions_table(ws, partchar[c], i);
	if (rc) {
          fprintf(stderr, "Failed to feed the versioning table for %c%d.db.\n", partchar[c], i);
	  errState = 1;
	  break;
	};
      };
    };
    if (errState)
      break;
  };

  if (errState)
    return 1;

  /**
   * 4 - For SQLite, we don't need to increate VARCHAR sizes - it automatically allows growing of sizes.
   */

  /**
   * 5 - Add CVSS scoring in CVE detail
   */
  sprintf(stmt, "SELECT sql FROM sqlite_master WHERE tbl_name = 'tb_cve' AND type = 'table';");
  PREPARE_SQLITE(rc, ws->localdb[0], stmt, sql_stmt)
  while ((rc = sqlite3_step(sql_stmt)) == SQLITE_ROW) {
    const unsigned char * sqltext;

    sqltext = sqlite3_column_text(sql_stmt, 0);
    // Casting sqltext from unsigned char to char because text should not
    // contain UTF-8 special characters so should be safe
    if (strstr((char *) sqltext, "cvss int") == NULL) {
      fprintf(stderr, "I am missing the cvss column in the tb_cve table. This is to be expected if you upgraded cvechecker from 3.1 or lower.\n");
      sprintf(stmt, "ALTER TABLE tb_cve ADD COLUMN cvss int DEFAULT -1;");
      rc = run_statement(ws, ws->localdb[0], stmt);
      if (rc) {
        fprintf(stderr, "Failed to execute SQL statement, bailing out...\n");
	errState = 1;
	break;
      };
      numChange++;
    };
  };
  ASSERT_FINALIZE(rc, stmt, sql_stmt)

  if (errState)
    return -errState;

  /**
   * 6 - Fieldsize of column contentmatch should be LARGEFIELDSIZE, not
   * FIELDSIZE.
   *
   * For SQLite, that doesn't matter, as the size in varchar(###) is ignored.
   */


  return numChange;
};

/**
 * Load the databases into the workstate
 *
 * The databases that are needed for the SQLite3 implementation are loaded in
 * the workstate variable. 
 */
int sqlite_dbimpl_load_databases(struct workstate * ws) {
  const config_setting_t * localdb;
  const config_setting_t * globaldb;
  int rc = 0;
  int i = 0;
  int c = 0;
  char buffer[BUFFERSIZE];
  char buffer2[BUFFERSIZE];

  /*
   * Load the set of databases
   */
  localdb = config_lookup(ws->cfg, "sqlite3.localdb");
  if (localdb == NULL) {
    fprintf(stderr, "Configuration file does not contain sqlite3.localdb directive.\n");
    return 1;
  };
  rc = strlen(config_setting_get_string(localdb));
  if (rc > FILENAMESIZE-1) {
    fprintf(stderr, "Configuration files 'sqlite3.localdb' directive cannot exceed %d characters\n", FILENAMESIZE-1);
    return 1;
  };

  strncpy(buffer, config_setting_get_string(localdb), rc);
  buffer[rc] = 0x00;
  strcat(buffer, "/");

  sprintf(buffer2, "%smain.db", buffer);
  rc = sqlite3_open(buffer2, &(ws->localdb[0]));
  if (rc) {
    fprintf(stderr, "Can't open database %s: %s\n", buffer2, sqlite3_errmsg(ws->localdb[0]));
    sqlite3_close(ws->localdb[0]);
    return rc;
  };

  rc = run_statement(ws, ws->localdb[0], "PRAGMA cache_size=10000;");
  if (rc) {
    fprintf(stderr, "Failed to run SQL statement, bailing out...\n");
    return rc;
  };

  rc = run_statement(ws, ws->localdb[0], "PRAGMA synchronous=OFF;");
  if (rc) {
    fprintf(stderr, "Failed to run SQL statement, bailing out...\n");
    return rc;
  };

  for (i = 1; i <= FIELDSIZE; i++) {
    for (c = 0; c < 3; c++) {
      sprintf(buffer2, "%s%c%d.db", buffer, partchar[c], i);
      rc = sqlite3_open(buffer2, &(ws->localdb[i+c*FIELDSIZE]));
      if (rc) {
        fprintf(stderr, "Can't open database %s: %s\n", buffer2, sqlite3_errmsg(ws->localdb[i+c*FIELDSIZE]));
        sqlite3_close(ws->localdb[i+c*FIELDSIZE]);
	return rc;
      } else {
        rc = run_statement(ws, ws->localdb[i+c*FIELDSIZE], "PRAGMA cache_size=10000;");
	if (rc) {
          fprintf(stderr, "Failed to execute statement, bailing out...\n");
	  return rc;
	};

        rc = run_statement(ws, ws->localdb[i+c*FIELDSIZE], "PRAGMA synchronous=OFF;");
	if (rc) {
	  fprintf(stderr, "Failed to execute statement, bailing out...\n");
	  return rc;
	};
      };
    };
  };
  
  globaldb = config_lookup(ws->cfg, "sqlite3.globaldb");
  if (globaldb == NULL) {
    fprintf(stderr, "Configuration file does not contain sqlite3.globaldb directive.\n");
    return 1;
  };
  i = strlen(config_setting_get_string(globaldb));
  if (i > FILENAMESIZE-1) {
    fprintf(stderr, "Configuration files 'sqlite3.globaldb' directive cannot exceed %d characters\n", FILENAMESIZE-1);
    return 1;
  };
  zero_string(buffer, BUFFERSIZE);
  strncpy(buffer, config_setting_get_string(globaldb), i);
  rc = sqlite3_open(buffer, &(ws->matchdb));
  if (rc) {
    fprintf(stderr, "Can't open database %s: %s\n", buffer, sqlite3_errmsg(ws->matchdb));
    sqlite3_close(ws->matchdb);
  };
  
  rc = run_statement(ws, ws->matchdb, "PRAGMA cache_size=10000;");
  if (rc) {
    fprintf(stderr, "Failed to execute statement, bailing out...\n");
    return rc;
  };

  rc = run_statement(ws, ws->matchdb, "PRAGMA synchronous=OFF;");
  if (rc) {
    fprintf(stderr, "Failed to execute statement, bailing out...\n");
    return rc;
  };

  if (! ws->arg->initdatabases) {
    rc = run_upgrade_fixes(ws);
    if (rc) {
      fprintf(stderr, "Some updates have occurred which might affect the database initialization.\n");
      fprintf(stderr, "Please restart the command.\n");
    };
  };

  return rc;
};

int add_to_sqlite_database(struct workstate * ws, struct cpe_data cpe) {
        int rc = 0;
	int cpeid = 0;
	int count = 0;
        char stmt[SQLLINESIZE];

        // Full match

        sprintf(stmt, "select count(*) from tb_cpe_%c_%zu where cpepart = \"%c\" and cpevendor = \"%s\" and cpeproduct = \"%s\" and cpeversion = \"%s\" and cpeupdate = \"%s\" and cpeedition = \"%s\" and cpelanguage = \"%s\";", cpe.part, strlen(cpe.vendor), cpe.part, cpe.vendor, cpe.product, cpe.version, cpe.update, cpe.edition, cpe.language);

        count = get_int_value(get_local_db(ws, cpe.part, strlen(cpe.vendor)), stmt, ws);

        if (count == 0) {
                sprintf(stmt, "insert into tb_cpe_%c_%zu (cpepart, cpevendor, cpeproduct, cpeversion, cpeupdate, cpeedition, cpelanguage) values (\"%c\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\");", cpe.part, strlen(cpe.vendor), cpe.part, cpe.vendor, cpe.product, cpe.version, cpe.update, cpe.edition, cpe.language);
                rc = run_statement(ws, get_local_db(ws, cpe.part, strlen(cpe.vendor)), stmt);
		if (rc) {
			fprintf(stderr, "Failed to execute statement, bailing out...\n");
			return rc;
		};

                zero_string(stmt, SQLLINESIZE);
                sprintf(stmt, "select count(cpeversion) from tb_cpe_versions where cpeversion = \"%s\";", cpe.version);
                count = get_int_value(get_local_db(ws, cpe.part, strlen(cpe.vendor)), stmt, ws);

                if (count == 0) {
                        int f[15];
                        int c;
                        for (c = 0; c < 15; c++)
                                f[c] = get_version_field(cpe.version, c);
                        zero_string(stmt, SQLLINESIZE);
                        sprintf(stmt, "INSERT INTO tb_cpe_versions (cpeversion, f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, f14, f15) values (\"%s\", %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d);", cpe.version, f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[9], f[10], f[11], f[12], f[13], f[14]);
                        rc = run_statement(ws, get_local_db(ws, cpe.part, strlen(cpe.vendor)), stmt); 
			if (rc) {
				fprintf(stderr, "Failed to execute statement, bailing out...\n");
				return rc;
			};
                };

                sprintf(stmt, "select cpeid from tb_cpe_%c_%zu where cpepart = \"%c\" and cpevendor = \"%s\" and cpeproduct = \"%s\" and cpeversion = \"%s\" and cpeupdate = \"%s\" and cpeedition = \"%s\" and cpelanguage = \"%s\";", cpe.part, strlen(cpe.vendor), cpe.part, cpe.vendor, cpe.product, cpe.version, cpe.update, cpe.edition, cpe.language);
        
                cpeid = get_int_value(get_local_db(ws, cpe.part, strlen(cpe.vendor)), stmt, ws);
        } else {
                sprintf(stmt, "select cpeid from tb_cpe_%c_%zu where cpepart = \"%c\" and cpevendor = \"%s\" and cpeproduct = \"%s\" and cpeversion = \"%s\" and cpeupdate = \"%s\" and cpeedition = \"%s\" and cpelanguage = \"%s\";", cpe.part, strlen(cpe.vendor), cpe.part, cpe.vendor, cpe.product, cpe.version, cpe.update, cpe.edition, cpe.language);
                cpeid = get_int_value(get_local_db(ws, cpe.part, strlen(cpe.vendor)), stmt, ws);
        };

        sprintf(stmt, "delete from tb_binmatch where basedir = \"%s\" and filename = \"%s\";", ws->currentdir, ws->currentfile);
        rc = run_statement(ws, ws->localdb[0], stmt);
	if (rc) {
		fprintf(stderr, "Failed to execute statement, bailing out...\n");
		return rc;
	};

        sprintf(stmt, "insert into tb_binmatch values ('%s', '%s', '%c', %zu, %d, 1);", ws->currentdir, ws->currentfile, cpe.part, strlen(cpe.vendor), cpeid);
        rc = run_statement(ws, ws->localdb[0], stmt);
	if (rc) {
		fprintf(stderr, "Failed to execute statement, bailing out...\n");
		return rc;
	};

	return 0;
};

/**
 * Add the selected CPE to the database
 */
int sqlite_dbimpl_add_cpe_to_database(struct workstate * ws, struct cpe_data cpe) {
	char buffer[BUFFERSIZE];

	add_to_sqlite_database(ws, cpe);
	cpe_to_string(buffer, BUFFERSIZE, cpe);
	fprintf(stdout, " - Added watch for %s\n", buffer);

	return 0;
};

int file_already_processed(struct workstate * ws) {
        int countResult = 0;
        char stmt[SQLLINESIZE];

        sprintf(stmt, "select count(*) from tb_binmatch where basedir = \"%s\" and filename = \"%s\";", ws->currentdir, ws->currentfile);

        countResult = get_int_value(ws->localdb[0], stmt, ws);

        if (countResult != 0) {
                return 1;
        };

        return 0;
};

/**
 * Process the results of the file-matching query.
 *
 * The file matching query should provide a list of possible matches. These
 * matches in the master database contain information on how to extract the
 * version of the (matching) file. This function will then use this information
 * to obtain the version from the file and store it in the database.
 */
int get_version_and_store(void * cbobj, int argc, char **argv, char **azColName) {
        int i, rc;
        char * file_name_expression = NULL;
        char * file_content_expression = NULL;
        regex_t preg;
        regmatch_t pmatch[16]; // Assuming no more than 16 groups are to be found
        struct cpe_data cpe_data;
        struct workstate * ws = (struct workstate *) cbobj;
        int filetype = 0;

        ws->rc=0;        // Re-init state

        for(i=0;i<argc;i++) {
                // One or more hits
                if (strcmp(azColName[i], "filematch") == 0) {
                        file_name_expression = argv[i];
                        continue;
                };
                if (strcmp(azColName[i], "contentmatch") == 0) {
                        file_content_expression = argv[i];
                        continue;
                };
                if (strcmp(azColName[i], "cpepart") == 0) {
                        cpe_data.part = argv[i][0];
                        continue;
                };
                if (strcmp(azColName[i], "cpevendor") == 0) {
                        strncpy(cpe_data.vendor, argv[i], 64);
                        continue;
                };
                if (strcmp(azColName[i], "cpeproduct") == 0) {
                        strncpy(cpe_data.product, argv[i], 64);
                        continue;
                };
                if (strcmp(azColName[i], "cpeversion") == 0) {
                        strncpy(cpe_data.version, argv[i], 64);
                        continue;
                };
                if (strcmp(azColName[i], "cpeupdate") == 0) {
                        strncpy(cpe_data.update, argv[i], 64);
                        continue;
                };
                if (strcmp(azColName[i], "cpeedition") == 0) {
                        strncpy(cpe_data.edition, argv[i], 64);
                        continue;
                };
                if (strcmp(azColName[i], "cpelanguage") == 0) {
                        strncpy(cpe_data.language, argv[i], 64);
                        continue;
                };
                if (strcmp(azColName[i], "filetype") == 0) {
                        filetype = atoi(argv[i]);
                        continue;
                };
        }

        // Verify if the filename matches file_name_expression
        rc = regcomp(&preg, file_name_expression, REG_EXTENDED);
        if (rc) {
                fprintf(stderr, "Failed to compile regular expression \"%s\"\n", file_name_expression);
                ws->rc = rc;
                return 0;
        };

        rc = regexec(&preg, ws->currentfile, 16, pmatch, 0);
        if (rc) {
                regfree(&preg);
                ws->rc = rc;
                return 0;
        };
        // Filename matches.

        // Free our memory allocations, and see if the content matches as well.
        regfree(&preg);
        rc = regcomp(&preg, file_content_expression, REG_EXTENDED);
        if (rc) {
                fprintf(stderr, "Failed to compile regular expression \"%s\"\n", file_content_expression);
                ws->rc = rc;
                return 0;
        };
        /**
         * Here is where the various version extraction methods are supported.
         * We currently still only support a single method (1, which is the
         * "strings -n 3 <file>" command execution) but now we can see if we can
         * support additional methods as well.
         */
        if (filetype == 1) {
                char buffer[BUFFERSIZE];
                int ret;

                zero_string(buffer, BUFFERSIZE);
                ret = strings_extract_version(ws, &preg, pmatch, &cpe_data);

                if (ret == 0) {
                        add_to_sqlite_database(ws, cpe_data);
                        cpe_to_string(buffer, BUFFERSIZE, cpe_data);
                        fprintf(stdout, " - Found match for %s/%s:\t%s\n", ws->currentdir, ws->currentfile, buffer);
                };
        } else {
                fprintf(stderr, " ! %s/%s: The sqlite3 implementation currently doesn't support file type %d\n", ws->currentdir, ws->currentfile, filetype);
        };
        ws->rc = 0;
        return 0;
}

/**
 * Delete the binary
 *
 * The binary file is provided through the workstate variable (currentfile and 
 * currentdir properties).
 */
int sqlite_dbimpl_delete_binary(struct workstate * ws) {
        char stmt[SQLLINESIZE];
	int rc;

        zero_string(stmt, SQLLINESIZE);

        sprintf(stmt, "delete from tb_binmatch where basedir = \"%s\" and filename = \"%s\";", ws->currentdir, ws->currentfile);
        rc = run_statement(ws, ws->localdb[0], stmt);

	return rc;
};

/**
 * Process the binary
 *
 * The binary file is provided through the workstate variable (currentfile and
 * currentdir properties).
 */
int sqlite_dbimpl_process_binary(struct workstate * ws) {
        char buffer[SQLLINESIZE];
        char * errmsg;

        int rc;

        zero_string(buffer, SQLLINESIZE);

        /*
         * Query: find match in master database for the file. If match found,
         * extract the version and store it in the local database.
         */
        strcpy(buffer, "select v.filename as filename, v.filetype as filetype, v.filematch as filematch, v.contentmatch as contentmatch, c.cpepart as cpepart, c.cpevendor as cpevendor, c.cpeproduct as cpeproduct, c.cpeversion as cpeversion, c.cpeupdate as cpeupdate, c.cpeedition as cpeedition, c.cpelanguage as cpelanguage from tb_versionmatch v, tb_cpe c where v.cpe = c.cpeid and \"");
        strcat(buffer, ws->currentfile);
        strcat(buffer,"\" between filename and filename || \"z\";");

        EXEC_SQLITE_RETURNFAIL(rc, ws->matchdb, buffer, get_version_and_store)

        return 0;
};

void find_cve_for_cpe(struct workstate * ws, char part, int length, int cpeid, const char * inset) {
  int rc = 0;
  int count;
  sqlite3_stmt * cve_stmt;
  char stmt[SQLLINESIZE];

  sprintf(stmt, "select count(*) from tb_cve");
  count = get_int_value(ws->localdb[0], stmt, ws);
  if (count == 0) {
    fprintf(stderr, "Local CVE Database is empty!\n");
    exit(EXIT_FAILURE);
   }; 

  sprintf(stmt, "select distinct a.basedir as basedir, a.filename as filename, b.year as year, b.sequence as sequence, b.cpe as cpeid, b.cvss as cvss from tb_binmatch a, tb_cve b where b.cpe in %s and a.cpe = %d and a.cpepart = b.cpepart and a.cpevendorlength = b.cpevendorlength;", inset, cpeid);

  PREPARE_SQLITE(rc, ws->localdb[0], stmt, cve_stmt)

  while ((rc = sqlite3_step(cve_stmt)) == SQLITE_ROW) {
    const unsigned char * basedir;
    const unsigned char * filename;
    char fullfilename[FILENAMESIZE];
    int year;
    int sequence;
    int cvssScore;
    int i;
    int realcpeid;
    struct cpe_data cpedata;


    basedir = sqlite3_column_text(cve_stmt, 0);
    filename = sqlite3_column_text(cve_stmt, 1);
    year = sqlite3_column_int(cve_stmt, 2);
    sequence = sqlite3_column_int(cve_stmt, 3);
    realcpeid = sqlite3_column_int(cve_stmt, 4);
    cvssScore = sqlite3_column_int(cve_stmt, 5);

    sprintf(fullfilename, "%s/%s", basedir, filename);

    zero_string(stmt, SQLLINESIZE);
    sprintf(stmt, "select cpepart, cpevendor, cpeproduct, cpeversion, cpeupdate, cpeedition, cpelanguage from tb_cpe_%c_%d where cpeid = %d;", part, length, cpeid);
    i = get_cpe_data(get_local_db(ws, part, length), stmt, ws);
    if (i != 0) {
      fprintf(stderr, "Request for CPE information that is not known to cvechecker!\n");
      exit(EXIT_FAILURE);
    };

    cpedata = ws->cpebuffer;
    ws->numresults = 0;

    if (realcpeid == cpeid) {
      i = 0;
    } else if (ws->arg->reporthigher) {
      i = 2;
    } else {
      i = 1;
    };

    show_potential_vulnerabilities(ws, year, sequence, cvssScore, fullfilename, cpedata, i);
  };
  ASSERT_FINALIZE(rc, stmt, cve_stmt)
};

void find_cpe_for_software(struct workstate * ws, char cpepart, int cpevendorlength, int cpe) {
  int rc = 0;
  sqlite3_stmt * cpe_stmt;
  char stmt[SQLLINESIZE*4];
  char inset1[SQLLINESIZE], inset2[SQLLINESIZE];

/*
   * We're going to perform two top queries.
   *
   * The first one returns the CPEs that are associated with the detected software. At least one should
   * be returned (cpeid == parentcpeid) but others might be (in case of non-core fields being set).
   *
   * The second one, which is optional (arg->reporthigher == 1), returns the CPEs that are associated 
   * with the detected software's core fields AND have a cpeversion field that has a higher value than
   * the current one. 
   */

  if (ws->arg->reporthigher == 0) {
    sprintf(stmt, "select a.cpeid as cpeid, b.cpeid as parentcpeid from tb_cpe_%c_%d a, tb_cpe_%c_%d b where "
    "(b.cpeid = %d) and "
    "(a.cpevendor = b.cpevendor) and "
    "(a.cpeproduct = b.cpeproduct) and "
    "( "
      "(a.cpeversion = b.cpeversion) or"
      "(b.cpeversion = \"\")"
    ") and "
    "( "
      "(a.cpeedition = b.cpeedition) or"
      "( "
        "(a.cpeedition != \"\" ) and "
	"(b.cpeedition = \"\")"
      ")"
    ") and "
    "( "
      "(a.cpeupdate = b.cpeupdate) or "
      "( "
        "(a.cpeupdate != \"\" ) and "
	"(b.cpeupdate = \"\" )"
      ") "
    ") and "
    "( "
      "(a.cpelanguage = b.cpelanguage) or "
      "( "
        "(a.cpelanguage != \"\") and "
	"(b.cpelanguage = \"\" )"
      ")"
    ");", cpepart, cpevendorlength, cpepart, cpevendorlength, cpe);
  } else {
    sprintf(stmt, "select a.cpeid as cpeid, b.cpeid as parentcpeid from tb_cpe_%c_%d a, tb_cpe_%c_%d b, tb_cpe_versions c, tb_cpe_versions d where "
    "(b.cpeid = %d) and "
    "(a.cpevendor = b.cpevendor) and "
    "(a.cpeproduct = b.cpeproduct) and "
    "("
    "  (a.cpeversion = c.cpeversion) and "
    "  (b.cpeversion = d.cpeversion) and "
    "  ("
    "    (c.f1 > d.f1) or "
    "    ("
    "      (c.f1 = d.f1) and "
    "      (c.f2 > d.f2)"
    "    ) or "
    "    ("
    "      (c.f1 = d.f1) and "
    "      (c.f2 = d.f2) and "
    "      (c.f3 > d.f3)"
    "    ) or "
    "    ("
    "      (c.f1 = d.f1) and "
    "      (c.f2 = d.f2) and "
    "      (c.f3 = d.f3) and "
    "      (c.f4 > d.f4)"
    "    ) or "
    "    ("
    "      (c.f1 = d.f1) and "
    "      (c.f2 = d.f2) and "
    "      (c.f3 = d.f3) and "
    "      (c.f4 = d.f4) and "
    "      (c.f5 > d.f5)"
    "    ) or "
    "    ("
    "      (c.f1 = d.f1) and "
    "      (c.f2 = d.f2) and "
    "      (c.f3 = d.f3) and "
    "      (c.f4 = d.f4) and "
    "      (c.f5 = d.f5) and "
    "      (c.f6 > d.f6)"
    "    ) or "
    "    ("
    "      (c.f1 = d.f1) and "
    "      (c.f2 = d.f2) and "
    "      (c.f3 = d.f3) and "
    "      (c.f4 = d.f4) and "
    "      (c.f5 = d.f5) and "
    "      (c.f6 = d.f6) and "
    "      (c.f7 > d.f7)"
    "    ) or "
    "    ("
    "      (c.f1 = d.f1) and "
    "      (c.f2 = d.f2) and "
    "      (c.f3 = d.f3) and "
    "      (c.f4 = d.f4) and "
    "      (c.f5 = d.f5) and "
    "      (c.f6 = d.f6) and "
    "      (c.f7 = d.f7) and "
    "      (c.f8 > d.f8)"
    "    ) or "
    "    ("
    "      (c.f1 = d.f1) and "
    "      (c.f2 = d.f2) and "
    "      (c.f3 = d.f3) and "
    "      (c.f4 = d.f4) and "
    "      (c.f5 = d.f5) and "
    "      (c.f6 = d.f6) and "
    "      (c.f7 = d.f7) and "
    "      (c.f8 = d.f8) and "
    "      (c.f9 > d.f9)"
    "    ) or "
    "    ("
    "      (c.f1 = d.f1) and "
    "      (c.f2 = d.f2) and "
    "      (c.f3 = d.f3) and "
    "      (c.f4 = d.f4) and "
    "      (c.f5 = d.f5) and "
    "      (c.f6 = d.f6) and "
    "      (c.f7 = d.f7) and "
    "      (c.f8 = d.f8) and "
    "      (c.f9 = d.f9) and "
    "      (c.f10 > d.f10)"
    "    ) or "
    "    ("
    "      (c.f1 = d.f1) and "
    "      (c.f2 = d.f2) and "
    "      (c.f3 = d.f3) and "
    "      (c.f4 = d.f4) and "
    "      (c.f5 = d.f5) and "
    "      (c.f6 = d.f6) and "
    "      (c.f7 = d.f7) and "
    "      (c.f8 = d.f8) and "
    "      (c.f9 = d.f9) and "
    "      (c.f10 = d.f10) and "
    "      (c.f11 > d.f11)"
    "    ) or "
    "    ("
    "      (c.f1 = d.f1) and "
    "      (c.f2 = d.f2) and "
    "      (c.f3 = d.f3) and "
    "      (c.f4 = d.f4) and "
    "      (c.f5 = d.f5) and "
    "      (c.f6 = d.f6) and "
    "      (c.f7 = d.f7) and "
    "      (c.f8 = d.f8) and "
    "      (c.f9 = d.f9) and "
    "      (c.f10 = d.f10) and "
    "      (c.f11 = d.f11) and "
    "      (c.f12 > d.f12)"
    "    ) or "
    "    ("
    "      (c.f1 = d.f1) and "
    "      (c.f2 = d.f2) and "
    "      (c.f3 = d.f3) and "
    "      (c.f4 = d.f4) and "
    "      (c.f5 = d.f5) and "
    "      (c.f6 = d.f6) and "
    "      (c.f7 = d.f7) and "
    "      (c.f8 = d.f8) and "
    "      (c.f9 = d.f9) and "
    "      (c.f10 = d.f10) and "
    "      (c.f11 = d.f11) and "
    "      (c.f12 = d.f12) and "
    "      (c.f13 > d.f13)"
    "    ) or "
    "    ("
    "      (c.f1 = d.f1) and "
    "      (c.f2 = d.f2) and "
    "      (c.f3 = d.f3) and "
    "      (c.f4 = d.f4) and "
    "      (c.f5 = d.f5) and "
    "      (c.f6 = d.f6) and "
    "      (c.f7 = d.f7) and "
    "      (c.f8 = d.f8) and "
    "      (c.f9 = d.f9) and "
    "      (c.f10 = d.f10) and "
    "      (c.f11 = d.f11) and "
    "      (c.f12 = d.f12) and "
    "      (c.f13 = d.f13) and "
    "      (c.f14 > d.f14)"
    "    ) or "
    "    ("
    "      (c.f1 = d.f1) and "
    "      (c.f2 = d.f2) and "
    "      (c.f3 = d.f3) and "
    "      (c.f4 = d.f4) and "
    "      (c.f5 = d.f5) and "
    "      (c.f6 = d.f6) and "
    "      (c.f7 = d.f7) and "
    "      (c.f8 = d.f8) and "
    "      (c.f9 = d.f9) and "
    "      (c.f10 = d.f10) and "
    "      (c.f11 = d.f11) and "
    "      (c.f12 = d.f12) and "
    "      (c.f13 = d.f13) and "
    "      (c.f14 = d.f14) and "
    "      (c.f15 > d.f15)"
    "    ) or "
    "    ("
    "      (c.f1 = d.f1) and "
    "      (c.f2 = d.f2) and "
    "      (c.f3 = d.f3) and "
    "      (c.f4 = d.f4) and "
    "      (c.f5 = d.f5) and "
    "      (c.f6 = d.f6) and "
    "      (c.f7 = d.f7) and "
    "      (c.f8 = d.f8) and "
    "      (c.f9 = d.f9) and "
    "      (c.f10 = d.f10) and "
    "      (c.f11 = d.f11) and "
    "      (c.f12 = d.f12) and "
    "      (c.f13 = d.f13) and "
    "      (c.f14 = d.f14) and "
    "      (c.f15 = d.f15)" 
    "    )"
    "  )"
    ") and "
    "( "
    "  (a.cpeedition = b.cpeedition) or "
    "  ( "
    "    (a.cpeedition != \"\" ) and "
    "        (b.cpeedition = \"\") "
    "  ) "
    ") and "
    "( "
    "  (a.cpeupdate = b.cpeupdate) or "
    "    ( "
    "      (a.cpeupdate != \"\" ) and "
    "      (b.cpeupdate = \"\" ) "
    "    ) "
    ") and "
    "( "
    "  (a.cpelanguage = b.cpelanguage) or "
    "  ( "
    "    (a.cpelanguage != \"\") and "
    "    (b.cpelanguage = \"\" ) "
    "  ) "
    ");", cpepart, cpevendorlength, cpepart, cpevendorlength, cpe);
  }
  PREPARE_SQLITE(rc, get_local_db(ws, cpepart, cpevendorlength), stmt, cpe_stmt)

  zero_string(inset1, SQLLINESIZE);
  sprintf(inset1, "(");
  while ((rc = sqlite3_step(cpe_stmt)) == SQLITE_ROW) {
    int cpeid;

    cpeid = sqlite3_column_int(cpe_stmt, 0);
    sprintf(inset2, "%s%d,", inset1, cpeid);
    strcpy(inset1, inset2);
  };
  sprintf(inset2, "%s0)", inset1);
  ASSERT_FINALIZE(rc, stmt, cpe_stmt)

  find_cve_for_cpe(ws, cpepart, cpevendorlength, cpe, inset2);
};


void new_dbimpl_verify_installed_versus_cve(struct workstate * ws) {
  int rc = 0;
  char stmt[SQLLINESIZE];
  sqlite3_stmt * fe_installed;

  /*
   * Steps:
   * 1. Find all installed software (dbimpl_verify_installed_versus_cve)
   * 2. For each software, find affected cpes (find_cpe_for_software())
   * 3. For each cpe, find CVEs (find_cve_for_cpe()) and report
   */

  sprintf(stmt, "select distinct cpepart, cpevendorlength, cpe from tb_binmatch order by cpepart, cpevendorlength, cpe;");
  PREPARE_SQLITE(rc, ws->localdb[0], stmt, fe_installed)

  while ((rc = sqlite3_step(fe_installed)) == SQLITE_ROW) {
    char cpepart;
    int cpevendorlength;
    int cpe;

    cpepart = sqlite3_column_text(fe_installed, 0)[0];
    cpevendorlength = sqlite3_column_int(fe_installed, 1);
    cpe = sqlite3_column_int(fe_installed, 2);
    find_cpe_for_software(ws, cpepart, cpevendorlength, cpe);
  };
  ASSERT_FINALIZE(rc, stmt, fe_installed)
};

int sqlite_dbimpl_verify_installed_versus_cve(struct workstate * ws) {
  new_dbimpl_verify_installed_versus_cve(ws);

  return 0;
};

int sqlite_dbimpl_initialize_workstate(struct workstate * ws) {
        int i = 0;

        ws->matchdb = NULL;
        ws->localdb = (sqlite3 **) calloc(sizeof(sqlite3 *), FIELDSIZE*3+1);
        for (i = 0; i <= FIELDSIZE*3; i++) {
                ws->localdb[i] = NULL;
        };

	return 0;
};

int check_cvecpe_in_sqlite_db(struct workstate * ws, int year, int sequence, struct cpe_data cpe) {
        int rc = 0;
        char stmt[SQLLINESIZE];

        sprintf(stmt, "select cpeid from tb_cpe_%c_%zu where cpepart = \"%c\" and cpevendor = \"%s\" and cpeproduct = \"%s\" and cpeversion = \"%s\" and cpeupdate = \"%s\" and cpeedition = \"%s\" and cpelanguage = \"%s\";", cpe.part, strlen(cpe.vendor), cpe.part, cpe.vendor, cpe.product, cpe.version, cpe.update, cpe.edition, cpe.language);

        rc = get_int_value(get_local_db(ws, cpe.part, strlen(cpe.vendor)), stmt, ws);

        if (rc == 0) {
                sprintf(stmt, "insert into tb_cpe_%c_%zu (cpepart, cpevendor, cpeproduct, cpeversion, cpeupdate, cpeedition, cpelanguage) values (\"%c\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\");", cpe.part, strlen(cpe.vendor), cpe.part, cpe.vendor, cpe.product, cpe.version, cpe.update, cpe.edition, cpe.language);
                rc = run_statement(ws, get_local_db(ws, cpe.part, strlen(cpe.vendor)), stmt);
		if (rc) {
			fprintf(stderr, "Failed to execute statement, bailing out...\n");
			return -1;
		};

                zero_string(stmt, SQLLINESIZE);
                sprintf(stmt, "select count(cpeversion) from tb_cpe_versions where cpeversion = \"%s\";", cpe.version);
                rc = get_int_value(get_local_db(ws, cpe.part, strlen(cpe.vendor)), stmt, ws);

                if (rc == 0) {
                        int f[15];
                        int c;
                        for (c = 0; c < 15; c++)
                                f[c] = get_version_field(cpe.version, c);
                        zero_string(stmt, SQLLINESIZE);
                              sprintf(stmt, "INSERT INTO tb_cpe_versions (cpeversion, f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, f14, f15) values (\"%s\", %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d);", cpe.version, f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[9], f[10], f[11], f[12], f[13], f[14]);

                };


                sprintf(stmt, "select cpeid from tb_cpe_%c_%zu where cpepart = \"%c\" and cpevendor = \"%s\" and cpeproduct = \"%s\" and cpeversion = \"%s\" and cpeupdate = \"%s\" and cpeedition = \"%s\" and cpelanguage = \"%s\";", cpe.part, strlen(cpe.vendor), cpe.part, cpe.vendor, cpe.product, cpe.version, cpe.update, cpe.edition, cpe.language);
                rc = get_int_value(get_local_db(ws, cpe.part, strlen(cpe.vendor)), stmt, ws);
        };

        sprintf(stmt, "select count(*) from tb_cve where year = %d and sequence = %d and cpepart = '%c' and cpevendorlength = %zu and cpe = %d;", year, sequence, cpe.part, strlen(cpe.vendor), rc);
        rc = get_int_value(ws->localdb[0], stmt, ws);
        return rc;
};

/**
 * Store the passed CVE entry in the database
 */
int sqlite_dbimpl_store_cve_in_db(struct workstate * ws, char * cveId, char * cpeId, char * cvssNum) {
        int rc = 0;
        char stmt[SQLLINESIZE];
        int year, sequence, cvssScore;
        struct cpe_data cpe;

        rc = cve_to_vars(&year, &sequence, cveId);
        if (rc == 1) {
                return 1;
        };
        string_to_cpe(&cpe, cpeId);

	cvssScore = atoi(cvssNum);
	cvssScore = cvssScore * 10 + atoi(strchr(cvssNum, '.')+1);

        ws->rc = 0;
        rc = check_cvecpe_in_sqlite_db(ws, year, sequence, cpe);
        if (rc != 0) {
                return 1;
        };

        sprintf(stmt, "select cpeid from tb_cpe_%c_%zu where cpepart = \"%c\" and cpevendor = \"%s\" and cpeproduct = \"%s\" and cpeversion = \"%s\" and cpeupdate = \"%s\" and cpeedition = \"%s\" and cpelanguage = \"%s\";",  cpe.part, strlen(cpe.vendor), cpe.part, cpe.vendor, cpe.product, cpe.version, cpe.update, cpe.edition, cpe.language);
        rc = get_int_value(get_local_db(ws, cpe.part, strlen(cpe.vendor)), stmt, ws);

        sprintf(stmt, "insert into tb_cve values (%d, %d, '%c', %zu, %d, %d);", year, sequence, cpe.part, strlen(cpe.vendor), rc, cvssScore);
        rc = run_statement(ws, ws->localdb[0], stmt);

        return rc;
};


/**
 * Add versiongather entry into the database
 */
int sqlite_dbimpl_add_versiongather(struct workstate * ws, struct versiongather_data vg, struct cpe_data cpe) {
        char stmt[SQLLINESIZE];
        char stmt2[SQLLINESIZE];
        int cpid = 0;
	int rc;

        sprintf(stmt, "select cpeid from tb_cpe where cpepart = \"%c\" and cpevendor = \"%s\" and cpeproduct = \"%s\" and cpeversion = \"%s\" and cpeupdate = \"%s\" and cpeedition = \"%s\" and cpelanguage = \"%s\";", cpe.part, cpe.vendor, cpe.product, cpe.version, cpe.update, cpe.edition, cpe.language);

        cpid = get_int_value(ws->matchdb, stmt, ws);

        if (cpid == 0) {
                zero_string(stmt2, SQLLINESIZE);
                sprintf(stmt2, "insert into tb_cpe (cpepart, cpevendor, cpeproduct, cpeversion, cpeupdate, cpeedition, cpelanguage) values (\"%c\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\");", cpe.part, cpe.vendor, cpe.product, cpe.version, cpe.update, cpe.edition, cpe.language);
                rc = run_statement(ws, ws->matchdb, stmt2);
		if (rc) {
			fprintf(stderr, "Failed to execute statements, bailing out...\n");
			return rc;
		};

                cpid = get_int_value(ws->matchdb, stmt, ws);
        };

        if (cpid == 0) {
                fprintf(stderr, "Failed to store new data!\n");
                return 1;
        };

        zero_string(stmt2, SQLLINESIZE);
        sprintf(stmt2, "insert into tb_versionmatch values (\"%s\", %d, \"%s\", \"%s\", %d);", vg.filepart, vg.gathertype, vg.filematch, vg.versionexpression, cpid);
        rc = run_statement(ws, ws->matchdb, stmt2);

        return rc;
};

/**
 * Initialize the databases
 */
int sqlite_dbimpl_initialize_databases(struct workstate * ws) {
  char stmt[SQLLINESIZE];
  int size = 1;
  int c = 0;
  int rc = 0;

  // Setup of global
  sprintf(stmt, "PRAGMA foreign_keys=OFF; BEGIN TRANSACTION; DROP TABLE IF EXISTS tb_versionmatch; DROP TABLE IF EXISTS tb_cpe; CREATE TABLE tb_versionmatch (filename varchar(%d), filetype smallint, filematch varchar(%d), contentmatch varchar(%d), cpe int); CREATE INDEX vmidx ON tb_versionmatch (filename); CREATE TABLE tb_cpe (cpeid integer primary key, cpepart char(1), cpevendor varchar(%d), cpeproduct varchar(%d), cpeversion varchar(%d), cpeupdate varchar(%d), cpeedition varchar(%d), cpelanguage varchar(%d)); COMMIT;", FILENAMESIZE, FILENAMESIZE, LARGEFIELDSIZE, FIELDSIZE, FIELDSIZE, FIELDSIZE, FIELDSIZE, FIELDSIZE, FIELDSIZE);
  rc = run_statement(ws, ws->matchdb, stmt);
  if (rc)
    return rc;

  // Setup of locals
  zero_string(stmt, SQLLINESIZE);
  sprintf(stmt, "PRAGMA foreign_keys=OFF; BEGIN TRANSACTION; DROP TABLE IF EXISTS tb_binmatch; DROP TABLE IF EXISTS tb_cve; CREATE TABLE tb_binmatch ( basedir varchar(%d), filename varchar(%d), cpepart char(1), cpevendorlength int, cpe int, fullmatch int); CREATE TABLE tb_cve ( year smallint, sequence int, cpepart char(1), cpevendorlength int, cpe int, cvss int); CREATE INDEX cveidx ON tb_cve (year, sequence); CREATE INDEX cveidx2 on tb_cve (cpe, cpepart, cpevendorlength); CREATE INDEX binmatchidx on tb_binmatch (cpe, cpepart, cpevendorlength); COMMIT;", FILENAMESIZE, FILENAMESIZE);
  rc = run_statement(ws, ws->localdb[0], stmt);
  if (rc) 
    return rc;

  for (size = 1; size <= FIELDSIZE; size++) {
    for (c = 0; c < 3; c++) {
      zero_string(stmt, SQLLINESIZE);
      sprintf(stmt, "DROP TABLE IF EXISTS tb_cpe_%c_%d; CREATE TABLE tb_cpe_%c_%d (cpeid integer primary key, cpepart char(1), cpevendor char(%d), cpeproduct char(%d), cpeversion char(%d), cpeupdate char(%d), cpeedition char(%d), cpelanguage char(%d)); CREATE INDEX cpe_%c_%d_idx on tb_cpe_%c_%d (cpevendor, cpeproduct, cpeversion, cpeid, cpeedition, cpeupdate, cpelanguage);", partchar[c], size, partchar[c], size, FIELDSIZE, FIELDSIZE, FIELDSIZE, FIELDSIZE, FIELDSIZE, FIELDSIZE, partchar[c], size, partchar[c], size);
      rc = run_statement(ws, get_local_db(ws, partchar[c], size), stmt);
      if (rc)
        return rc;
      sprintf(stmt, "DROP TABLE IF EXISTS tb_cpe_versions; CREATE TABLE tb_cpe_versions (cpeversion char(%d) primary key, f1 integer, f2 integer, f3 integer, f4 integer, f5 integer, f6 integer, f7 integer, f8 integer, f9 integer, f10 integer, f11 integer, f12 integer, f13 integer, f14 integer, f15 integer); CREATE INDEX cpe_versions_idx on tb_cpe_versions (cpeversion); CREATE INDEX cpe_versions_2_idx on tb_cpe_versions (f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, f14, f15);", FIELDSIZE);
      rc = run_statement(ws, get_local_db(ws, partchar[c], size), stmt);
      if (rc)
        return rc;
    };
  };
  
  return 1;
};

/**
 * Report on detected software/versions
 */
int sqlite_dbimpl_report_installed(struct workstate * ws, int showfiles) {
  char stmt[SQLLINESIZE];
  char * errmsg;
  int size;
  int rc;
  int c;

  for (size = 1; size <= FIELDSIZE; size++) {
    for (c = 0; c < 3; c++) {
      sprintf(stmt, "SELECT DISTINCT cpepart, cpevendorlength, cpe FROM tb_binmatch WHERE cpepart = '%c' AND cpevendorlength = %d;", partchar[c], size);
      ws->rc = showfiles;
      EXEC_SQLITE(rc, ws->localdb[0], stmt, get_cpelist)
    };
  };

  return 0;
};

/**
 * Initialization for storing CVE data in the database.
 *
 * The initialization function is meant to allow implementations
 * to optimize their functions (like starting a transaction scope).
 */
int sqlite_dbimpl_store_cve_in_db_init(struct workstate * ws) {
        // do nothing
	return 0;
};

/**
 * Exit method for finalizing the storage of CVE data in the database.
 *
 * The exit method is meant to allow implementations to optimize their functions
 * (like committing at the transaction scope).
 */
int sqlite_dbimpl_store_cve_in_db_exit(struct workstate * ws) {
        // do nothing
	return 0;
};

/**
 * Checkpoint method for the CVE upload process
 */
int sqlite_dbimpl_store_cve_in_db_checkpoint(struct workstate * ws) {
  return 0;
};

/**
 * Initialize arguments structure with database-specific fields
 */
int sqlite_dbimpl_initialize_arguments(struct arguments * arg) {
        // do nothing
	return 0;
};



/**
 * Check if sqlite is built in
 */
int sqlite_dbimpl_supported() {
  return 1;
};
