#!/usr/bin/perl
use FindBin;          
use lib $FindBin::Bin;
use DumpDex;
use Getopt::Std;

	my %opts;
	getopts('v',\%opts);

	if (@ARGV == 0) {&usage};

	open my $tempfh,"$ARGV[0]" or die "Unable to open $ARGV[0]\n";

	my $dex = DumpDex->new($tempfh,\%opts);

	my $DexChecksum = $dex->CalcDexFileChecksum;
	my $hdrchksum = sprintf "%x", $dex->{Checksum};

	if ( $DexChecksum eq $hdrchksum)
	{
		printf "Checksum correct.\n";
		if ($opts{v})
		{
			printf "Checksum(in header):\t0x%s\nCalculated checksum:\t0x%s\n", $hdrchksum, $DexChecksum;
		}	    
	}
	else
	{
		printf "Checksum bad.\n";
		if ($opts{v})
		{
			printf "Checksum(in header):\t0x%s\nCalculated checksum:\t0x%s\n", $hdrchksum, $DexChecksum;
		}	    
	    
	}
	




sub usage {
die <<END_USAGE
dexcksum - Android DEX File Checksum Verifier ver. 0.1
Copyright 2012 Jimmy Shah  All rights reserved.

Usage: $0 filename

Options:

    -v  Verbose
    
END_USAGE
}
