EXTRA_DIST = \
             acknowledgements.xml  report.xsl csv2xml.awk cvereport.xsl report.css mysql_cvechecker.sql
exampledir = $(datarootdir)/doc/@PACKAGE@
example_DATA = acknowledgements.xml
cvecheckerdir = $(datarootdir)/cvechecker
cvechecker_DATA = cvereport.xsl report.css csv2xml.awk mysql_cvechecker.sql

install-data-local:
	@mkdir_p@ "$(DESTDIR)${localstatedir}/cvechecker" \
	          "$(DESTDIR)${localstatedir}/cvechecker/local" \
		  "$(DESTDIR)${localstatedir}/cvechecker/cache"

uninstall-local:
	echo "Beware, 'make uninstall' will not remove any of the following locations:"
	echo " - $(DESTDIR)${localstatedir}/cvechecker/cache"
	echo " - $(DESTDIR)${localstatedir}/cvechecker/local"
	echo " - $(DESTDIR)${localstatedir}/cvechecker"
