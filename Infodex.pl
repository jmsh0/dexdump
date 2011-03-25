#!/usr/bin/perl
use FindBin;          
use lib $FindBin::Bin;
use DumpDex;
use Getopt::Std;

my %opts;
getopts('asmcftn',\%opts);

open my $tempfh,"$ARGV[0]" or die "Unable to open $ARGV[0]\n";

my $dex = DumpDex->new($tempfh,\%opts);

&DumpHdr;

if ($opts{a} || $opts{s})
{
	$dex->DumpStrings;
}
if ($opts{a} || $opts{m})
{
	$dex->DumpMethods;
}
if ($opts{a} || $opts{c})
{
	$dex->GetClassDefs;
}
if ($opts{a} || $opts{f})
{
	$dex->DumpFieldIDs;
}
if ($opts{a} || $opts{t})
{
	$dex->DumpTypeIDs;
}

exit;


sub DumpHdr
{
	print "=========DEX Header=================\n";
	print "Magic => " . $dex->{Magic};
	printf "Checksum => %#08x\n", $dex->{Checksum};
	printf "SHA-1 => %s\n", unpack('H*', $dex->{Signature});
	printf "File Size => %d\n", $dex->{FileSize};
	printf "Header Length => %#02x\n", $dex->{HdrLength};
	printf "Link Section Size => %#08x\n", $dex->{LinkSectionSize};
	printf "Link Section Offset => %#08x\n", $dex->{LinkSectionOff};
	printf "Map Item Offset => %#08x\n", $dex->{MapSectionOff};
	printf "String IDs Count => %#08x\n", $dex->{StringIdentifiersCount};
	printf "String IDs Offset => %#08x\n", $dex->{StringIdentifiersOffset};
	printf "Type IDs Count => %#08x\n", $dex->{TypeIdentifiersCount};
	printf "Type IDs Offset => %#08x\n", $dex->{TypeIdentifiersOffset};
	printf "Prototype IDs Count => %#08x\n", $dex->{PrototypeIdentifiersCount};
	printf "Prototype IDs  Offset => %#08x\n", $dex->{PrototypeIdentifiersOffset}; 
	printf "Field IDs Count  => %#08x\n", $dex->{FieldIdentifiersCount};
	printf "Field IDs Offset => %#08x\n", $dex->{FieldIdentifiersOffset}; 
	printf "Method IDs Count  => %#08x\n", $dex->{MethodIdentifiersCount};  
	printf "Method IDs Offset => %#08x\n", $dex->{MethodIdentifiersOffset}; 
	printf "Class IDs Count  => %#08x\n", $dex->{ClassIdentifiersCount};  
	printf "Class IDs Offset => %#08x\n", $dex->{ClassIdentifiersOffset}; 
	printf "Data IDs Count  => %#08x\n", $dex->{DataIdentifiersCount};  
	printf "Data IDs Offset => %#08x\n", $dex->{DataIdentifiersOffset}; 
	print "--------------------------------------------\n";
	
	
}






