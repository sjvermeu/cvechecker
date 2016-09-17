# cvechecker

The goal of cvechecker is to report about possible vulnerabilities on your
system, by scanning a list of installed software and matching results with
the CVE database. This is not a bullet-proof method and you will have many false positives (ie: vulnerability is fixed with a revision-release, but the tool isn't able to detect the revision itself), yet it is still better than nothing, especially if you are running a distribution with little security coverage.

### Quickstart
--------------
1. Initalize the SQLite3 Database  
    ```~# cvechecker -i```

2. Load CVE and version matching rules  
    ```~$ pullcves pull```

3. Generate List of Files to scan  
    ```~$ find / -type f -perm -o+x > scanlist.txt```
    ```~$ echo "/proc/version" >> scanlist.txt```

4. Gather List of Installed Software/Versions  
    ```~$ cvechecker -b scanlist.txt```

5. Output Matching CVE Entries  
    ```~$ cvechecker -r```

More detailed installation information available via the [installation docs](../../wiki/Installation).  
[The homepage for this project](../../wiki).
