#!/usr/bin/perl

#use diagnostics;
use DumpLib;
use Getopt::Std;

our %opts;
getopts('asmcft',\%opts);

if (@ARGV == 0) {&usage};
open my $tempfh,"$ARGV[0]" or die "Unable to open $ARGV[0]\n";


	
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
if ($opts{a} || $opts{c})
{
	&GetClasses;
}
if ($opts{a} || $opts{f})
{
	&DumpFieldIDs;
}
if ($opts{a} || $opts{t})
{
	&DumpTypeIDs;
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
	
	&initAccessFlags;
	&GetStrings;
	&GetTypeIDs;
	&GetPrototypes;
	&GetFieldIDs;
	&GetMethods;
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
	print "--------------------------------------------\n";
	
	
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

sub GetFieldIDs
{
	
	my $offset = $dex->{FieldIdentifiersOffset};
	my @fields;
	
	for(my $n = 0; $n < $dex->{FieldIdentifiersCount}; $n++, $offset += 8)	
	{
		
		
		$fields[$n] = 	[GetClassID($dex->get_word($offset)), GetClassID($dex->get_word($offset+2)), $dex->{StringIDs}[$dex->get_long($offset+4)]]
	}
	
	$dex->{FieldIDs} = [@fields];	
		
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

sub GetTypeIDs
{
	my $offset = $dex->{TypeIdentifiersOffset};
	
	my @types;

	for(my $n = 0; $n < $dex->{TypeIdentifiersCount}; $n++, $offset += 4)	
	{
		$types[$n] = $dex->{StringIDs}[$dex->get_long($offset)];
	}

	$dex->{TypeIDs} = [@types];	
}

sub GetMethods
{
	my $offset = $dex->{MethodIdentifiersOffset};
	
	my @methods;

	for(my $n = 0; $n < $dex->{MethodIdentifiersCount}; $n++, $offset += 8)	
	{
		$methods[$n] = [GetClassID($dex->get_word($offset)),ProtToType($dex->{StringIDs}[$dex->{PrototypeIDs}[$dex->get_word($offset+2)][0]]),$dex->{StringIDs}[$dex->get_long($offset+4)]];
	}

	$dex->{Methods} = [@methods];	
}


sub GetClassID
{
	my $index = shift;
	
	my $ClassOffset = $index * 4; 
	
	$ClassOffset += $dex->{TypeIdentifiersOffset};
	
	return $dex->{StringIDs}[$dex->get_long($ClassOffset)];
}




sub initAccessFlags
{
	my %accFlags;
	$accFlags{public} = 0x1;
	$accFlags{private} = 0x2;
	$accFlags{protected} = 0x4;
	$accFlags{static} = 0x8;
	$accFlags{final} = 0x10;
	$accFlags{synchronized} = 0x20;
	$accFlags{volatile} = 0x40;
	$accFlags{bridge} = 0x40;
	$accFlags{transient} = 0x80;
	$accFlags{varargs} = 0x80;
	$accFlags{native} = 0x100;
	$accFlags{interface} = 0x200;
	$accFlags{abstract} = 0x400;
	$accFlags{strict} = 0x800;
	$accFlags{synthetic} = 0x1000;
	$accFlags{annotation} = 0x2000;
	$accFlags{enum} = 0x4000;
	$accFlags{constructor} = 0x10000;
	$accFlags{declared_synchronized} = 0x20000;	 
		
	$dex->{AccessFlags} = {%accFlags};
}



sub DumpStrings
{
	for(my $n = 0; $n < $dex->{StringIdentifiersCount}; $n++)
	{
			printf "%x:\t%s\n", $n, $dex->{StringIDs}[$n];
	}
	
}

sub DumpTypeIDs
{
	for(my $n = 0; $n < $dex->{TypeIdentifiersCount}; $n++)
	{
			printf "%x:\t%s\n", $n, $dex->{TypeIDs}[$n];
	}
	
}

sub DumpFieldIDs
{
	for(my $n = 0; $n < $dex->{FieldIdentifiersCount}; $n++)
	{
		printf "FieldID %#04x:\n", $n;
		printf "\tClass\t\t%s\n", $dex->{FieldIDs}[$n][0];	
		printf "\tType\t\t%s\n", $dex->{FieldIDs}[$n][1];	
		printf "\tName\t\t%s\n", $dex->{FieldIDs}[$n][2]; 
		print "\t--------------------------------------------\n";
	}
	
}

sub DumpMethods
{
	my $offset = $dex->{MethodIdentifiersOffset};
	
	print "=========Methods=================\n";
	for(my $n = 0; $n < $dex->{MethodIdentifiersCount}; $n++)	
	{
		printf "Method %#04x:\n", $n; 
		printf "\tClass\t\t%s\n", $dex->{Methods}[$n][0];	
		printf "\tPrototype\t%s\n", $dex->{Methods}[$n][1];
		
		printf "\tName\t\t%s\n", $dex->{Methods}[$n][2];
		print "\t--------------------------------------------\n";
	}
}

sub GetClasses
{
	my $offset = $dex->{ClassIdentifiersOffset};

	#print "=========Classes=================\n";
	for(my $n = 0; $n < $dex->{ClassIdentifiersCount}; $n++)	
	{
       	my ($classname, $accflags, $superclass, $interfaces, $source, $annotations, $classdata, $staticval);
		$classname = GetClassID($dex->get_long($offset));
        printf "\tClass\t\t%s\n", $classname;
		$offset += 4;

		$accflags = GetAccFlags($dex->get_long($offset));
        printf "\tAccess Flags: \t%s\n", $accflags;
		$offset += 4;
	
		my $sclassindex = $dex->get_long($offset);
		if ($sclassindex != 0xFFFFFFFF)
		{
			$superclass = GetClassID($sclassindex);
	        printf "\tSuperclass\t%s\n", $superclass;
		}
		$offset += 4;
		
		my $ifaceOffset = $dex->get_long($offset);
		if ($ifaceOffset)
		{
			my $ifacelistsize = $dex->get_long($ifaceOffset);
			$ifaceOffset += 4;
			
			for (my $n = 0; $n < $ifacelistsize;$n++)
			{
				$interfaces .= "\t\t\t" . GetClassID($dex->get_word($ifaceOffset)) . "\n";
			}
			
			printf "\tInterfaces:\n%s", $interfaces;
		}	
		$offset += 4;

		$source = $dex->{StringIDs}[$dex->get_long($offset)];
		printf "\tSource file\t%s\n", $source;
		$offset += 4;

	#	annotations_off
		my $annotOffset = $dex->get_long($offset);
	
			if ($annotOffset)
			{

				my $annotClassOffset = $dex->get_long($annotOffset);
				$annotOffset += 4;

				my $fieldCount = $dex->get_long($annotOffset);
				$annotOffset += 4;

				my $methodsCount = $dex->get_long($annotOffset);
				$annotOffset += 4;

				my $paramsCount = $dex->get_long($annotOffset);
				$annotOffset += 4;

				if($fieldCount)
				{
					for(my $n = 0; $n < $fieldCount;$n++)
					{
						printf "%08#x", $dex->{FieldIDs}[$dex->get_long($annotOffset)][2];
						$annotOffset += 4;

						my $annotSetItemoffset = $dex->get_long($annotOffset);
						my $annotSetItemSize = $dex->get_long($annotSetItemoffset);
						for(my $i = 0; $i < $annotSetItemSize; $i++,$annotSetItemoffset += 4)
						{
							printf "Visibiity: %s\n", GetVisibilityFlags($dex->get_byte($annotSetItemoffset));$annotSetItemoffset++;
							printf "Type: %s\n", $dex->{TypeIDs}[$dex->get_uleb128(\$annotSetItemoffset)];
							my $enc_annot_size = $dex->get_uleb128(\$annotSetItemoffset);
							   
							for(my $m = 0;$m < $enc_annot_size; $m++  )
							{
								printf "Annotation Name: %s\n",$dex->{StringIDs}[$dex->get_uleb128(\$annotSetItemoffset)];
							  	
							}
						}
					}
				}
				
				if($methodsCount)
				{
					for(my $n = 0; $n < $methodsCount;$n++)
					{
						printf "%08#x", $dex->{FieldIDs}[$dex->get_long($annotOffset)][2];
						$annotOffset += 4;
						
						
					}
					
				}
				
				if($params_size)
				{
					for(my $n = 0; $n < $fieldCount;$n++)
					{
						
					}
					
				}
	
	
			#method_annotations 	method_annotation[methods_size] (optional) 	list of associated method annotations. The elements of the list must be sorted in increasing order, by method_idx.
			#parameter_annotations
						
			}	
			else
			{
				printf "\tNo Annotations\n";
			}
		$offset += 4;
	#	class_data_off
		$offset += 4;
	#	static_values_off
	
		$offset += 4;
		print "\t--------------------------------------------\n";
#	$dex->{Classes} = [];
	
        }



}

# class_data_off->class_data_item->code_item

# Convenience functions

sub ProtToType
{
	my $proto = shift;
	
	$proto =~ s/V/void /g;
	$proto =~ s/Z/boolean /g;
	$proto =~ s/B/byte /g;
	$proto =~ s/S/short /g;
	$proto =~ s/C/char /g;
	$proto =~ s/I/int /g;
	$proto =~ s/J/long /g;
	$proto =~ s/F/float /g;
	$proto =~ s/D/double /g;
	
	return $proto;
	
}

sub GetAccFlags
{
	my $flags = shift;
	my $flagtxt;
	
		
	if ($flags & $dex->{AccessFlags}{public})
	{
		
		$flagtxt .= "public ";	
	}
	
		
	if ($flags & $dex->{AccessFlags}{private})
	{
		
		$flagtxt .= "private ";	
	}
		
	if ($flags & $dex->{AccessFlags}{protected})
	{
		
		$flagtxt .= "protected ";	
	}
	
	if ($flags & $dex->{AccessFlags}{static})
	{
		
		$flagtxt .= "static ";	
	}
	
	if ($flags & $dex->{AccessFlags}{final})
	{
		
		$flagtxt .= "final ";	
	}
	
	if ($flags & $dex->{AccessFlags}{synchronized})
	{
		
		$flagtxt .= "synchronized ";	
	}
	
	if ($flags & $dex->{AccessFlags}{bridge})
	{
		
		$flagtxt .= "bridge ";	
	}
	
	if ($flags & $dex->{AccessFlags}{transient})
	{
		
		$flagtxt .= "transient ";	
	}
	
	if ($flags & $dex->{AccessFlags}{varargs})
	{
		
		$flagtxt .= "varargs ";	
	}
	
	if ($flags & $dex->{AccessFlags}{native})
	{
		
		$flagtxt .= "native ";	
	}
	
	if ($flags & $dex->{AccessFlags}{interface})
	{
		
		$flagtxt .= "interface ";	
	}
	
	if ($flags & $dex->{AccessFlags}{abstract})
	{
		
		$flagtxt .= "abstract ";	
	}
	
	if ($flags & $dex->{AccessFlags}{strict})
	{
		
		$flagtxt .= "strict ";	
	}
	
	if ($flags & $dex->{AccessFlags}{synthetic})
	{
		
		$flagtxt .= "synthetic ";	
	}
	
	if ($flags & $dex->{AccessFlags}{annotation})
	{
		
		$flagtxt .= "annotation ";	
	}
	if ($flags & $dex->{AccessFlags}{enum})
	{
		
		$flagtxt .= "enum ";	
	}
	
	if ($flags & $dex->{AccessFlags}{constructor})
	{
		
		$flagtxt .= "constructor ";	
	}
	
	if ($flags & $dex->{AccessFlags}{declared_synchronized})
	{
		
		$flagtxt .= "declared_synchronized ";	
	}
	
	return $flagtxt;		
	
}

sub GetVisibilityFlags
{
	my $flags = shift;
	
	if ($flags == 0x0)
	{
		return "Build";	
	}
	if ($flags == 0x1)
	{
		return "Runtime"
	}
	if ($flags == 0x2)
	{
		return "System"	
	}
}

sub EncodedValues
{
	#	TODO
	
}