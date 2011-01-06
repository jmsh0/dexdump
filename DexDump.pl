#!/usr/bin/perl

#use diagnostics;
use DumpLib;
use Getopt::Std;

our %opts;
getopts('asm',\%opts);

if (@ARGV == 0) {&usage};
open my $tempfh,"$ARGV[0]";


	
our $dex = DumpLib->new($tempfh,\%opts);

&init;
&DumpHdr;
if ($opts{a} || $opts{s})
{
	&DumpStrings;
}
if ($opts{a} || $opts{m})
{
	&DumpMethods;
}

sub init
{
	$dex->{Magic} =                     $dex->get_string(0x0,8);
	$dex->{Magic} =~ s/\n/ /; $dex->{Magic} = $dex->{Magic} . "\n";
	
	$dex->{Checksum} =                  $dex->get_long(0x8);
	$dex->{Signature} =                	$dex->get_chunk(0xC, 20);
	
	$dex->{FileSize}  =     	        $dex->get_long(0x20);
	$dex->{HdrLength} =                 $dex->get_long(0x24);
	$dex->{LinkSectionSize} =           $dex->get_long(0x2C);
	$dex->{LinkSectionOff} =           	$dex->get_long(0x30);
	$dex->{MapSectionOff} =           	$dex->get_long(0x34);
	$dex->{StringIdentifiersCount} =    $dex->get_long(0x38);
	$dex->{StringIdentifiersOffset} =   $dex->get_long(0x3C);
	$dex->{TypeIdentifiersCount} =    	$dex->get_long(0x40);
	$dex->{TypeIdentifiersOffset} =   	$dex->get_long(0x44);
	$dex->{PrototypeIdentifiersCount} =  $dex->get_long(0x48);
	$dex->{PrototypeIdentifiersOffset} = $dex->get_long(0x4C);
	$dex->{FieldIdentifiersCount} =		$dex->get_long(0x50);
	$dex->{FieldIdentifiersOffset} = 	$dex->get_long(0x54);
	$dex->{MethodIdentifiersCount} =  	$dex->get_long(0x58);
	$dex->{MethodIdentifiersOffset} = 	$dex->get_long(0x5c);
	$dex->{ClassIdentifiersCount} =  	$dex->get_long(0x60);
	$dex->{ClassIdentifiersOffset} = 	$dex->get_long(0x64);
	$dex->{DataIdentifiersCount} =  	$dex->get_long(0x68);
	$dex->{DataIdentifiersOffset} = 	$dex->get_long(0x6c);
	
	&GetStrings;
	&GetPrototypes;
}

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
	
	
	
}

sub GetStrings
{
	my $offset = $dex->{StringIdentifiersOffset};
	my @strings;
	
	for(my $n = 0; $n < $dex->{StringIdentifiersCount}; $n++, $offset += 4)	
	{
		$strings[$n] = 	$dex->get_stringL($dex->get_long($offset));
	}
	
		$dex->{StringIDs} = [@strings];	
}

sub GetPrototypes
{
	my $offset = $dex->{PrototypeIdentifiersOffset};
	
	my @prototypes;

	for(my $n = 0; $n < $dex->{PrototypeIdentifiersCount}; $n++, $offset += 12)	
	{
		$prototypes[$n] = [$dex->get_long($offset),$dex->get_long($offset+4),$dex->get_long($offset+8)];
	}

	$dex->{PrototypeIDs} = [@prototypes];	
}


sub GetClassID
{
	my $offset = shift;
	
	my $ClassOffset = $dex->get_word($$offset) * 4; 
	
	$ClassOffset += $dex->{TypeIdentifiersOffset};
	
	$$offset += 2;
	
	return $dex->{StringIDs}[$dex->get_long($ClassOffset)];
}

sub GetPrototypeID
{
	my $offset = shift;
	
		my $PrototypeOffset = $dex->get_word($offset) * 4; 
		
		$PrototypeOffset += $dex->{PrototypeIdentifiersOffset};
	
		
	
		$$offset += 2;
	
	return $dex->{StringIDs}[$dex->get_long($PrototypeOffset)]
	
}





sub DumpStrings
{
	for(my $n = 0; $n < $dex->{StringIdentifiersCount}; $n++)
	{
		printf "%x:\t%s\n", $n, $dex->{StringIDs}[$n];
		
	}
	
}



sub DumpMethods
{
	
	my $offset = $dex->{MethodIdentifiersOffset};
	
	print "=========Methods=================\n";
	for(my $n = 0; $n < $dex->{MethodIdentifiersCount}; $n++)	
	{
		printf "Method %#08x:\n", $n; 
		printf "\tClass\t%s\n", GetClassID(\$offset);	
		
		printf "\tPrototype\t%s\n", $dex->{StringIDs}[$dex->{PrototypeIDs}[$dex->get_word($offset)][0]];$offset += 2;
		printf "\tName\t%s\n", $dex->{StringIDs}[$dex->get_long($offset)]; $offset += 4;
	}
}





