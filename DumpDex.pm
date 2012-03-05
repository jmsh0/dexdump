package DumpDex;

use Carp;
use FindBin;          
use lib $FindBin::Bin;
use DumpLib;
use Archive::Zip qw( :ERROR_CODES :CONSTANTS );
use File::Temp;
use Digest::Adler32;

sub new ()
{ 
  my ($this,$fname,$options) = @_;
  my $class = ref($this) || $this; 
  my $self = {}; 
   
  bless $self, $class;

  $self->{InpF} = DumpLib->new($fname);
  $self->{options} = $options;
  
  if($self->IsZip)
  {
	my $zip = Archive::Zip->new($self->{InpF}->{FH});
	unless($zip)
	{
		croak "Error opening Zip/APK file.\n";
	}
	my @AndMF = $zip->membersMatching('AndroidManifest.xml');

	unless(@AndMF)
	{
		croak "Invalid APK: Missing AndroidManifest.xml\n";	
	}

	my @CDex = $zip->membersMatching('classes.dex');

	if (@CDex)
	{
		my $DexDir = File::Temp->newdir();

		my $ClassesDex = File::Temp->new( TEMPLATE => 'tempXXXXX', DIR =>  $DexDir->dirname, SUFFIX => '.dex');
    
		unless($CDex[0]->extractToFileNamed($ClassesDex->filename) == AZ_OK)
		{
			croak "Unable to extract classes.dex.\n";
		}
		
		# open tmp classes.dex, pass filehandle to object
		open my $fh,$ClassesDex->filename or croak "Cannot open classes.dex\n";
		binmode $fh;
		
		$self->{InpF}->{FH} = $fh;
		
	}
	else
	{
		croak "Invalid APK: Missing classes.dex\n";	
	}
  }
 
  my $IsDex = $self->init;
  if ($IsDex)
  {
        return $self; 
  }
  else
  {
        return undef;  
  }
}


sub IsZip
{
	my $self = shift;
	
	if (0x04034b50 == $self->{InpF}->get_long(0x0))
	{
		return 1;		
	}
	else
	{
		return undef;	
	} 
	
}

sub init
{
	my $self = shift;
	$self->{Magic} =                     $self->{InpF}->get_string(0x0,8);
	unless($self->{Magic} =~ /^dex/) 
	{
		croak "Invalid classes.dex: Bad Magic number"
	}
	$self->{Magic} =~ s/\n/ /; $self->{Magic} = $self->{Magic} . "\n";
	$self->{Checksum} =                  $self->{InpF}->get_long(0x8);
	$self->{Signature} =                	$self->{InpF}->get_chunk(0xC, 20);
	$self->{FileSize}  =     	        $self->{InpF}->get_long(0x20);
	$self->{HdrLength} =                 $self->{InpF}->get_long(0x24);
	$self->{LinkSectionSize} =           $self->{InpF}->get_long(0x2C);
	$self->{LinkSectionOff} =           	$self->{InpF}->get_long(0x30);
	$self->{MapSectionOff} =           	$self->{InpF}->get_long(0x34);
	$self->{StringIdentifiersCount} =    $self->{InpF}->get_long(0x38);
	$self->{StringIdentifiersOffset} =   $self->{InpF}->get_long(0x3C);
	$self->{TypeIdentifiersCount} =    	$self->{InpF}->get_long(0x40);
	$self->{TypeIdentifiersOffset} =   	$self->{InpF}->get_long(0x44);
	$self->{PrototypeIdentifiersCount} =  $self->{InpF}->get_long(0x48);
	$self->{PrototypeIdentifiersOffset} = $self->{InpF}->get_long(0x4C);
	$self->{FieldIdentifiersCount} =		$self->{InpF}->get_long(0x50);
	$self->{FieldIdentifiersOffset} = 	$self->{InpF}->get_long(0x54);
	$self->{MethodIdentifiersCount} =  	$self->{InpF}->get_long(0x58);
	$self->{MethodIdentifiersOffset} = 	$self->{InpF}->get_long(0x5c);
	$self->{ClassIdentifiersCount} =  	$self->{InpF}->get_long(0x60);
	$self->{ClassIdentifiersOffset} = 	$self->{InpF}->get_long(0x64);
	$self->{DataIdentifiersCount} =  	$self->{InpF}->get_long(0x68);
	$self->{DataIdentifiersOffset} = 	$self->{InpF}->get_long(0x6c);
	
	$self->initAccessFlags;
	$self->GetStrings;
	$self->GetTypeIDs;
	$self->GetPrototypes;
	$self->GetFieldIDs;
	$self->GetMethods;
}

sub initAccessFlags
{
	my $self = shift;
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
		
	$self->{AccessFlags} = {%accFlags};
}

sub GetStrings
{
	my $self = shift;
	
	my $offset = $self->{StringIdentifiersOffset};
	my @strings;
	
	for(my $n = 0; $n < $self->{StringIdentifiersCount}; $n++, $offset += 4)	
	{
		$strings[$n] = 	$self->{InpF}->get_stringL($self->{InpF}->get_long($offset));
	}
	
	$self->{StringIDs} = [@strings];	
}

sub GetTypeIDs
{
	my $self = shift;
	
	my $offset = $self->{TypeIdentifiersOffset};
	
	my @types;

	for(my $n = 0; $n < $self->{TypeIdentifiersCount}; $n++, $offset += 4)	
	{
		$types[$n] = $self->{StringIDs}[$self->{InpF}->get_long($offset)];
	}

	$self->{TypeIDs} = [@types];	
}

sub GetPrototypes
{
	my $self = shift;
	
	my $offset = $self->{PrototypeIdentifiersOffset};
	
	my @prototypes;

	for(my $n = 0; $n < $self->{PrototypeIdentifiersCount}; $n++, $offset += 12)	
	{
		$prototypes[$n] = [$self->{InpF}->get_long($offset),$self->{InpF}->get_long($offset+4),$self->{InpF}->get_long($offset+8)];
	}

	$self->{PrototypeIDs} = [@prototypes];	
}

sub GetClassID
{
	my ($self,$index) = @_;
	
	my $ClassOffset = $index * 4; 
	
	$ClassOffset += $self->{TypeIdentifiersOffset};
	
	return $self->{StringIDs}[$self->{InpF}->get_long($ClassOffset)];
}





sub GetFieldIDs
{
	my $self = shift;
		
	my $offset = $self->{FieldIdentifiersOffset};
	my @fields;
	
	for(my $n = 0; $n < $self->{FieldIdentifiersCount}; $n++, $offset += 8)	
	{
		$fields[$n] = 	[$self->GetClassID($self->{InpF}->get_word($offset)), $self->GetClassID($self->{InpF}->get_word($offset+2)), $self->{StringIDs}[$self->{InpF}->get_long($offset+4)]]
	}
	
	$self->{FieldIDs} = [@fields];	
		
}

sub GetMethods
{
	my $self = shift;
	
	my $offset = $self->{MethodIdentifiersOffset};
	
	my @methods;

	for(my $n = 0; $n < $self->{MethodIdentifiersCount}; $n++, $offset += 8)	
	{
		$methods[$n] = [$self->GetClassID($self->{InpF}->get_word($offset)),$self->ProtToType($self->{StringIDs}[$self->{PrototypeIDs}[$self->{InpF}->get_word($offset+2)][0]]),$self->{StringIDs}[$self->{InpF}->get_long($offset+4)]];
	}

	$self->{Methods} = [@methods];	
}

sub DumpStrings
{
	my $self = shift;
	
	for(my $n = 0; $n < $self->{StringIdentifiersCount}; $n++)
	{
			printf "%x:\t%s\n", $n, $self->{StringIDs}[$n];
	}
	
}

sub DumpTypeIDs
{
	my $self = shift;

	for(my $n = 0; $n < $self->{TypeIdentifiersCount}; $n++)
	{
			printf "%x:\t%s\n", $n, $self->{TypeIDs}[$n];
	}
	
}


sub DumpFieldIDs
{
	my $self = shift;

	for(my $n = 0; $n < $self->{FieldIdentifiersCount}; $n++)
	{
		printf "FieldID %#04x:\n", $n;
		printf "\tClass\t\t%s\n", $self->{FieldIDs}[$n][0];	
		printf "\tType\t\t%s\n", $self->{FieldIDs}[$n][1];	
		printf "\tName\t\t%s\n", $self->{FieldIDs}[$n][2]; 
		print "\t--------------------------------------------\n";
	}
	
}

sub DumpMethods
{
	my $self = shift;

	my $offset = $self->{MethodIdentifiersOffset};
	
	print "=========Methods=================\n";
	for(my $n = 0; $n < $self->{MethodIdentifiersCount}; $n++)	
	{
		printf "Method %#04x:\n", $n; 
		printf "\tClass\t\t%s\n", $self->{Methods}[$n][0];	
		printf "\tPrototype\t%s\n", $self->{Methods}[$n][1];
		printf "\tName\t\t%s\n", $self->{Methods}[$n][2];
		print "\t--------------------------------------------\n";
	}
}

sub GetClassDefs
{
	my $self = shift;
	
	my $offset = $self->{ClassIdentifiersOffset};

	#print "=========Classes=================\n";
	for(my $n = 0; $n < $self->{ClassIdentifiersCount}; $n++)	
	{
       	my ($classname, $accflags, $superclass, $interfaces, $source, $annotations, $classdata, $staticval);
		$classname = $self->GetClassID($self->{InpF}->get_long($offset));
        printf "\tClass\t\t%s\n", $classname;
		$offset += 4;

		$accflags = $self->GetAccFlags($self->{InpF}->get_long($offset));
        printf "\tAccess Flags: \t%s\n", $accflags;
		$offset += 4;
	
		my $sclassindex = $self->{InpF}->get_long($offset);
		if ($sclassindex != 0xFFFFFFFF)
		{
			$superclass = $self->GetClassID($sclassindex);
	        printf "\tSuperclass\t%s\n", $superclass;
		}
		$offset += 4;
		
		my $ifaceOffset = $self->{InpF}->get_long($offset);
		if ($ifaceOffset)
		{
			my $ifacelistsize = $self->{InpF}->get_long($ifaceOffset);
			$ifaceOffset += 4;
			
			for (my $n = 0; $n < $ifacelistsize;$n++)
			{
				$interfaces .= "\t\t\t" . $self->GetClassID($self->{InpF}->get_word($ifaceOffset)) . "\n";
			}
			
			printf "\tInterfaces:\n%s", $interfaces;
		}	
		$offset += 4;

		$source = $self->{StringIDs}[$self->{InpF}->get_long($offset)];
		printf "\tSource file\t%s\n", $source;
		$offset += 4;

	#	TODO: annotations_off
		if ($opts{a} || $opts{n})
		{
			$self->GetAnnots($self->{InpF}->get_long($offset));
		}
		$offset += 4;
		
	#	class_data_off
		$offset += 4;
	#	static_values_off
	
		$offset += 4;
		print "\t--------------------------------------------\n";
#	$dex->{Classes} = [];
# class_data_off->class_data_item->code_item	
    }
}


sub GetAnnots
{
	my ($self,$annotOffset) = @_;

	if ($annotOffset)
			{

				my $annotClassOffset = $self->{InpF}->get_long($annotOffset);
				$annotOffset += 4;

				my $fieldCount = $self->{InpF}->get_long($annotOffset);
				$annotOffset += 4;

				my $methodsCount = $self->{InpF}->get_long($annotOffset);
				$annotOffset += 4;

				my $paramsCount = $self->{InpF}->get_long($annotOffset);
				$annotOffset += 4;

				if($fieldCount)
				{
					print "\t--------------------------------------------\n";
					for(my $n = 0; $n < $fieldCount;$n++)
					{
						printf "\tAnnotation\n\t\tField:\t%s\n", $self->{FieldIDs}[$self->{InpF}->get_long($annotOffset)][2];
						$annotOffset += 4;

						my $annotSetItemoffset = $self->{InpF}->get_long($annotOffset);
						$annotOffset += 4;
						my $annotSetItemSize = $self->{InpF}->get_long($annotSetItemoffset);
						for(my $i = 0; $i < $annotSetItemSize; $i++,$annotSetItemoffset += 4)
						{
							printf "\t\tVisibiity: %s\n", $self->GetVisibilityFlags($self->{InpF}->get_byte($annotSetItemoffset));$annotSetItemoffset++;
							printf "\t\tType: %s\n", $self->{TypeIDs}[$self->{InpF}->get_uleb128(\$annotSetItemoffset)];
							my $enc_annot_size = $self->{InpF}->get_uleb128(\$annotSetItemoffset);
							   
							for(my $m = 0;$m < $enc_annot_size; $m++  )
							{
								printf "Annotation Name: %s\n",$self->{StringIDs}[$self->{InpF}->get_uleb128(\$annotSetItemoffset)];
							  	
							}
						}
					}
				}
				
				if($methodsCount)
				{
					print "\t--------------------------------------------\n";
					for(my $n = 0; $n < $methodsCount;$n++)
					{
						printf "\tAnnotation\n\t\tMethod:\t%s\n", $self->{Methods}[$self->{InpF}->get_long($annotOffset)][2];
						$annotOffset += 4;
						
						my $annotSetItemoffset = $self->{InpF}->get_long($annotOffset);
						$annotOffset += 4;
						my $annotSetItemSize = $self->{InpF}->get_long($annotSetItemoffset);
#						$annotSetItemoffset += 4;
						for(my $i = 0; $i < $annotSetItemSize; $i++,$annotSetItemoffset += 4)
						{
							printf "\t\tVisibiity: %s\n", $self->GetVisibilityFlags($self->{InpF}->get_byte($annotSetItemoffset));$annotSetItemoffset++;
							printf "\t\tType: %s\n", $self->{TypeIDs}[$self->{InpF}->get_uleb128(\$annotSetItemoffset)];
							my $enc_annot_size = $self->{InpF}->get_uleb128(\$annotSetItemoffset);
							
							printf "Annot Meth Enc Annot: %x\n", $annotSetItemoffset;   
							for(my $m = 0;$m < $enc_annot_size; $m++  )
							{
								printf "Annotation Name: %s\n",$self->{StringIDs}[$self->{InpF}->get_uleb128(\$annotSetItemoffset)];
							  	
							}
						}
					}
				}
				
				if($paramsCount)
				{
					print "Annot: Params\n----------------\n";
					for(my $n = 0; $n < $fieldCount;$n++)
					{
						printf "%08#x", $self->{FieldIDs}[$self->{InpF}->get_long($annotOffset)][2];
						$annotOffset += 4;
						
						my $annotSetItemoffset = $self->{InpF}->get_long($annotOffset);
						my $annotSetItemSize = $self->{InpF}->get_long($annotSetItemoffset);
						for(my $i = 0; $i < $annotSetItemSize; $i++,$annotSetItemoffset += 4)
						{
							printf "Visibiity: %s\n", $self->GetVisibilityFlags($self->{InpF}->get_byte($annotSetItemoffset));$annotSetItemoffset++;
							printf "Type: %s\n", $self->{TypeIDs}[$self->{InpF}->get_uleb128(\$annotSetItemoffset)];
							my $enc_annot_size = $self->{InpF}->get_uleb128(\$annotSetItemoffset);
							   
							for(my $m = 0;$m < $enc_annot_size; $m++  )
							{
								printf "Annotation Name: %s\n",$self->{StringIDs}[$self->{InpF}->get_uleb128(\$annotSetItemoffset)];
							  	
							}
						}
					}
				}
			}	
			else
			{
				printf "\tNo Annotations\n";
			}
}



# Convenience functions

sub ProtToType
{
	my ($self,$proto) = @_;
	
	$proto =~ s/V/void /g;
	$proto =~ s/Z/boolean /g;
	$proto =~ s/B/byte /g;
	$proto =~ s/S/short /g;
	$proto =~ s/C/char /g;
	$proto =~ s/I/int /g;
	$proto =~ s/J/long /g;
	$proto =~ s/F/float /g;
	$proto =~ s/D/double /g;
	$proto =~ s/L/L /g;
	
	return $proto;
	
}

sub GetAccFlags
{
	my ($self,$flags) = @_;
	my $flagtxt;
			
	if ($flags & $self->{AccessFlags}{public})
	{
		
		$flagtxt .= "public ";	
	}
	
		
	if ($flags & $self->{AccessFlags}{private})
	{
		
		$flagtxt .= "private ";	
	}
		
	if ($flags & $self->{AccessFlags}{protected})
	{
		
		$flagtxt .= "protected ";	
	}
	
	if ($flags & $self->{AccessFlags}{static})
	{
		
		$flagtxt .= "static ";	
	}
	
	if ($flags & $self->{AccessFlags}{final})
	{
		
		$flagtxt .= "final ";	
	}
	
	if ($flags & $self->{AccessFlags}{synchronized})
	{
		
		$flagtxt .= "synchronized ";	
	}
	
	if ($flags & $self->{AccessFlags}{bridge})
	{
		
		$flagtxt .= "bridge ";	
	}
	
	if ($flags & $self->{AccessFlags}{transient})
	{
		
		$flagtxt .= "transient ";	
	}
	
	if ($flags & $self->{AccessFlags}{varargs})
	{
		
		$flagtxt .= "varargs ";	
	}
	
	if ($flags & $self->{AccessFlags}{native})
	{
		
		$flagtxt .= "native ";	
	}
	
	if ($flags & $self->{AccessFlags}{interface})
	{
		
		$flagtxt .= "interface ";	
	}
	
	if ($flags & $self->{AccessFlags}{abstract})
	{
		
		$flagtxt .= "abstract ";	
	}
	
	if ($flags & $self->{AccessFlags}{strict})
	{
		
		$flagtxt .= "strict ";	
	}
	
	if ($flags & $self->{AccessFlags}{synthetic})
	{
		
		$flagtxt .= "synthetic ";	
	}
	
	if ($flags & $self->{AccessFlags}{annotation})
	{
		
		$flagtxt .= "annotation ";	
	}
	if ($flags & $self->{AccessFlags}{enum})
	{
		
		$flagtxt .= "enum ";	
	}
	
	if ($flags & $self->{AccessFlags}{constructor})
	{
		
		$flagtxt .= "constructor ";	
	}
	
	if ($flags & $self->{AccessFlags}{declared_synchronized})
	{
		
		$flagtxt .= "declared_synchronized ";	
	}
	
	return $flagtxt;		
	
}

sub GetVisibilityFlags
{
	my ($self,$flags) = @_;
	
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

sub CalcDexFileChecksum
{
	my ($self) = shift;

	my $checksumH = Digest::Adler32->new;

	$checksumH->add($self->{InpF}->get_chunk(0xC,$self->{FileSize} - 0xC ));

	return $checksumH->hexdigest;	
	
}

1;