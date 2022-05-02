bin_SCRIPTS = pullcves cvereport cvegenversdat cverules
EXTRA_DIST = cvedebian $(bin_SCRIPTS)

pullcves: pullcves.in
	sed 's|SYSCONFDIR|${sysconfdir}|g' $< > $@
