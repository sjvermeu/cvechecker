EXTRA_DIST = README.md LICENSE ChangeLog

SUBDIRS =  \
          src \
	  data \
	  conf \
	  scripts \
	  docs 

postinstall:
	getent group cvechecker > /dev/null 2>&1 || groupadd cvechecker
	chgrp cvechecker $(DESTDIR)$(localstatedir)/cvechecker
	chgrp cvechecker $(DESTDIR)$(localstatedir)/cvechecker/local
	chgrp cvechecker $(DESTDIR)$(localstatedir)/cvechecker/cache
	chmod g+w $(DESTDIR)$(localstatedir)/cvechecker
	chmod g+w $(DESTDIR)$(localstatedir)/cvechecker/local
	chmod g+w $(DESTDIR)$(localstatedir)/cvechecker/cache
