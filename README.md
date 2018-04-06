# dexdump

Utilities for analyzing Android malware, including
* __Infodex - Android DEX File Dumper__

    Usage: ./Infodex.pl [-asmcft] filename
    
    Options:
    
               -a   Dump all
               -s   Dump string table
               -m   Dump method table
               -c   Dump class table
               -f   Dump Fields
               -t   Display file type information

* __DmpAxml - AndroidManifest.xml File Dumper__

    Usage: ./DmpAxml.pl [-adspih] filename

    Options:

               -a  Dump all
               -d  Dump printable AndroidManifest.xml
               -s  Dump string table
               -p  Dump Permissions
               -i  Dump Intents
               -h  Run heuristics




* __dexcksum - Android DEX File Checksum Verifier__

    Usage: ./dexcksum.pl [-v] filename

    Options:

               -v  Verbose
