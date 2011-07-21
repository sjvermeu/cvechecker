CONFS = \
        cvechecker.conf
sysconf_DATA = cvechecker.conf

EXTRA_DIST = cvechecker.conf.in

edit = sed \
	-e 's|@localstatedir[@]|$(localstatedir)|g' \
	-e 's|@pkgdatadir[@]|$(pkgdatadir)|g'

cvechecker.conf:
	rm -f $@ $@.tmp
	srcdir=''; \
	  test -f ./$@.in || srcdir=$(srcdir)/; \
	  $(edit) $${srcdir}$@.in > $@.tmp

	chmod a-w $@.tmp
	mv $@.tmp $@
