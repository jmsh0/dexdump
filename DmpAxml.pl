#!/usr/bin/perl
###############################################################################
# This program is licensed under the GNU Public License, version 3 or later.
# A copy of this license is included in the package as License.txt.
# If it is missing, a copy is available at http://www.gnu.org/copyleft/gpl.html
###############################################################################
use FindBin;          
use lib $FindBin::Bin;
use DumpAxml;
use AxmlHeuristics;
use Getopt::Std;

my %opts;
getopts('aspidh',\%opts);

if (@ARGV == 0) {&usage};

open my $tempfh,"$ARGV[0]" or die "Unable to open $ARGV[0]\n";

my $axml = DumpAxml->new($tempfh,\%opts);

if ($opts{a} || $opts{s})
{
	$axml->DumpStrings;
}

if ($opts{a} || $opts{p})
{
	$axml->DumpPermissions;
}

if ($opts{a} || $opts{i})
{
	$axml->DumpIntents;
}



if ($opts{a} || $opts{d})
{
	$axml->DisplayPrintableAXML;
}

if ($opts{h})
{
	my $heur = AxmlHeuristics->new($axml);
	$heur->Run;
}


exit;





sub usage {
die <<END_USAGE
DmpAxml - AndroidManifest.xml File Dumper ver. 0.6
Copyright 2013 Jimmy Shah  All rights reserved.

Usage: $0 [-adspih] filename

Options:

    -a  Dump all
    -d  Dump printable AndroidManifest.xml
    -s  Dump string table
    -p  Dump Permissions
    -i  Dump Intents
    -h  Run heuristics

END_USAGE
}


