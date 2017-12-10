package DumpAxml;
###############################################################################
# This program is licensed under the GNU Public License, version 3 or later.
# A copy of this license is included in the package as License.txt.
# If it is missing, a copy is available at http://www.gnu.org/copyleft/gpl.html
###############################################################################

use Carp;
use FindBin;          
use lib $FindBin::Bin;
use DumpLib;
use Archive::Zip qw( :ERROR_CODES :CONSTANTS );
use File::Temp;
# use diagnostics;

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

	
	my $AndMFDir = File::Temp->newdir();

	my $AndroidManifest = File::Temp->new( TEMPLATE => 'tempXXXXX', DIR =>  $AndMFDir->dirname, SUFFIX => '.xml');

	unless($AndMF[0]->extractToFileNamed($AndroidManifest->filename) == AZ_OK)
	{
		croak "Unable to extract AndroidManifest.xml.\n";
	}
	
	# open tmp AndroidManifest.xml, pass filehandle to object
	open my $fh,$AndroidManifest->filename or croak "Cannot open AndroidManifest.xml\n";
	binmode $fh;
	
	$self->{InpF}->{FH} = $fh;
	
	
  }
 
  my $IsAndMF = $self->init;
  if ($IsAndMF)
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
	$self->{Magic} =                     $self->{InpF}->get_long(0x0,4);
	unless($self->{Magic} == 0x00080003)  # File Chunk
	{
		croak "Invalid AndroidManifest.xml: Bad Chunk number"
	}
	
	# Size of entire file == size of File chunk or 
	# all sub-chunks contained within file chunk
	$self->{FileChunkSize}  =     	        $self->{InpF}->get_long(0x04);
	$self->{Offset} = 0x8;
	$self->{Chunks} = $self->GetAllSubChunks;
	$self->{Permissions} = {};
	
	
	my @tagStack;
	
	while($#{ $self->{Chunks}} >=0)
	{
	  # handle strings first, then later loop 
	  $self->ProcessChunks;
	}
	
	$self->GetPermissions;
	$self->GetIntents;
	
	
	return 1;
}


sub GetAllSubChunks
{
	my $self = shift;
	my @Chunks;
	my $origOffset = $self->{Offset};
	while( $origOffset < $self->{FileChunkSize})
	{
		my $currentChunkType = $self->{InpF}->get_long($origOffset); 
		
# 		printf "(func call)currentChunkType: %#08x\n",$self->{InpF}->get_long($origOffset); 
# 		
# 		printf "origOffset: %#08x\n", $origOffset;
# 		printf "currentChunkType: %#08x\n", $currentChunkType;
		
		
		my $currentChunkLength = $self->{InpF}->get_long($origOffset + 4); 
		
# 		printf "origOffset: %#08x\n", $origOffset;
# 		printf "currentChunkLength: %#08x\n", $currentChunkLength;
		
		
		$origOffset += $currentChunkLength;
		
# 		printf "End chunk origOffset: %#08x\n", $origOffset;
		
		
		push @Chunks, [$currentChunkType, $currentChunkLength];
		
	
	}
	return \@Chunks;
}



sub ProcessChunks
{

	my $self = shift;
	
	while($#{ $self->{Chunks}} >=0)
	{
	  	if (0x001C0001 == $self->{Chunks}[$i][0])
		{
# 			print "Strings chunk -" . sprintf "%#08x\n",$self->{Chunks}[$i][0];
			my @CurrentChunk = shift @{$self->{Chunks}}; #clear strings chunk off chunk array
			$self->ProcessStringsChunk($self->{Offset});
			$self->{Offset} += $CurrentChunk[0][1];
			last;
		}
	  	elsif (0x080180 == $self->{Chunks}[$i][0])
		{
# 			print "Resource chunk -" . sprintf "%#08x\n",$self->{Chunks}[$i][0];
			my @CurrentChunk = shift @{$self->{Chunks}}; 
			$self->{ResourceIDs} = $self->ProcessResourceIDChunk($self->{Offset},$CurrentChunk[0][1]);
			$self->{Offset} += $CurrentChunk[0][1];
			last;
		}
		elsif (0x00100100 == $self->{Chunks}[$i][0])
		{
		
			$self->{PrintableAXML} .= sprintf "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
			
			while($#{ $self->{Chunks}} >= 0)
			{
			  $self->ProcessEncodedXML;
			}
			
		}
		else 
		{
			  die "Unknown chunk -" . sprintf "%#08x\n",$self->{Chunks}[$i][0]
		}
		
    	}
	



}

sub ProcessStringsChunk
{

	my ($self, $offset) = @_;

	my $StartStringChunk = $offset;
	
	# Strings chunk
		$offset += 4;
		$self->{StringChunkLength} = $self->{InpF}->get_long($offset);
	# Count of Strings
		$offset += 4;
		$self->{StringCount} = $self->{InpF}->get_long($offset);
	# Count of Styles
		$offset += 4;
		$self->{StyleCount} = $self->{InpF}->get_long($offset);
	# Skip to offset of string offsets
		$offset += 8;
		# actual offset from start of file
		$self->{StringTableOffset} = $self->{InpF}->get_long($offset);
		$self->{StringTableOffset} += $StartStringChunk;

		$offset += 8;
		$self->GetStrings($offset);

}




sub ProcessResourceIDChunk
{


	my ($self, $offset, $length) = @_;

# 	my $StartResourceChunk = $offset += 8;
# 	Skip Type + Length
	$offset += 8;

	# 	(Length - (Type[4 bytes] + Length[4 bytes]))/4 = number of ids
	$length -= 8;
	$length /= 4;
	
	for(my $n = 0; $n < $length; $n++)
	{
	    push @ResourceIDs, [$self->{InpF}->get_long($offset)];
	    $offset += 4;
	  
	}

	$self->{ResourceIDs} = [@ResourceIDs];
}


sub ProcessEncodedXML
{

	my $self = shift;
	my $depth = 0;

	while($#{ $self->{Chunks}} >=0)
	{
	      if (0x00100100 == $self->{Chunks}[0][0])
	      {
# 		Start Namespace
		@namespaces = $self->{Namespaces};

		my @CurrentChunk = shift @{$self->{Chunks}}; 
# 		skip to chunk data/value
		my $offset = $self->{Offset} + 8;
		
		my $LineNumber = $self->{InpF}->get_long($offset);
# 		skip past unknown value 0xFFFFFFFF
		$offset += 8;
		
# 		index into string table for prefix, generally always "android"
		my $PrefixIndex =  $self->{InpF}->get_long($offset); $offset += 4;
		
# 		index into string table for namespace, generally always "http://schemas.android.com/apk/res/android"
		my $NamespaceIndex = $self->{InpF}->get_long($offset); $offset += 4;

		$self->{Namespaces} = [$PrefixIndex, $NamespaceIndex];
		
		$self->{ManifestNamespace} = sprintf"xmlns:%s = \"%s", $self->{Strings}[$PrefixIndex],$self->{Strings}[$NamespaceIndex];

		$self->{Offset} += $CurrentChunk[0][1];
		last;
	      }
	      elsif (0x00100101 == $self->{Chunks}[0][0])
 	      {
# 		"End Namespace"
		my @CurrentChunk = shift @{$self->{Chunks}}; 
		$self->{Offset} += $CurrentChunk[0][1];
		last;
	      }
	      elsif (0x00100102 == $self->{Chunks}[0][0])
	      {
# 		"Start Tag"
		my @CurrentChunk = shift @{$self->{Chunks}}; 

		my $offset = $self->{Offset} + 8;

		my $LineNumber = $self->{InpF}->get_long($offset);
# 		skip past unknown value 0xFFFFFFFF
		$offset += 8;

# 		index into string table for namespace
		my $NamespaceIndex = $self->{InpF}->get_long($offset); $offset += 4;

		@namespaces = $self->{Namespaces};
		
		if ($namespaces[1] == $NamespaceIndex)
		{
		  my $namespace = $self->{Strings}[$namespaces[0]];
		}
		else
		{
		  my $namespace = "";
		}
		
		# 		index into string table for tag name
		my $NameIndex = $self->{InpF}->get_long($offset); $offset += 4;
		
		my $flag = $self->{InpF}->get_long($offset); $offset += 4;
		
		my $tagName = $self->{Strings}[$NameIndex];

		push @tagStack, $tagName;
		
		unless($NamespaceIndex == 0xFFFFFFFF) 
		{
		  $self->{PrintableAXML} .= sprintf "<%s : \"%s\"\n", $tagName ,$namespace;

		}
		else
		{
		  $self->{PrintableAXML} .= sprintf "%s<%s ", "    " x $self->{indentDepth},$tagName;
		
		}
		
		my $NumAttributes = $self->{InpF}->get_word($offset); $offset += 2;
# 		skip id,clas,style attributes
		$offset += 6;
		
		for (my $n = 0;$n < $NumAttributes;$n++)
		{
# 		index into string table for namespace
		    my $NamespaceIndex = $self->{InpF}->get_long($offset); $offset += 4;
		    
		    my $namespace;
		    
		    if ($self->{Namespaces}[1] == $NamespaceIndex)
		    {
		      $namespace = $self->{Strings}[$self->{Namespaces}[0]];
		    }
		    else
		    {
		      $namespace = "";
		    }
		    
		    # index into string table for attribute name
		    my $NameIndex = $self->{InpF}->get_long($offset); $offset += 4;
# 		    skip att String 
		    $offset += 4;
		    
		    my $attType = $self->{InpF}->get_long($offset); $offset += 4;
		    
		    my $attValue = $self->{InpF}->get_long($offset); $offset += 4;
		    
		    my $name = $self->{Strings}[$NameIndex];

		    
		    unless($NamespaceIndex == 0xFFFFFFFF) 
		    {
		      $self->{PrintableAXML} .= sprintf "%s:%s ", $namespace,$self->{Strings}[$NameIndex];

		    }
		    else
		    {
		      $self->{PrintableAXML} .= sprintf "%s ", $self->{Strings}[$NameIndex];
		    
		    }


    		    if (($attType >> 24) == 3)
		    {
		      $AttributeValue = $self->{Strings}[$attValue];
		    }
		    else
		    {
		      $AttributeValue = $attValue;
		    
		    }

		    $self->{PrintableAXML} .= sprintf "= \"%s\" ",  $AttributeValue;
		
		}
		
		if ($self->{indentDepth} == 0)
		{
		    $self->{PrintableAXML} .= sprintf "\n  %s\">\n", $self->{ManifestNamespace};
		}

		else
		{
		    $self->{PrintableAXML} .=  sprintf ">\n";
		}

# 		handle depth of indents
		$self->{indentDepth} += 1;
		
		$self->{Offset} += $CurrentChunk[0][1];
		last;
	      }
	      elsif (0x00100103 == $self->{Chunks}[0][0])
	      {
# 		"End Tag";
		my @CurrentChunk = shift @{$self->{Chunks}}; 

# 		skip to chunk data/value
		my $offset = $self->{Offset} + 8;
			
		
		$self->{Offset} += $CurrentChunk[0][1];
		my $tagName = pop @tagStack ;
		
		$self->{indentDepth} -= 1;
		$self->{PrintableAXML} .= sprintf "    " x $self->{indentDepth} . "</$tagName>\n";
  
		
		last;
	      }
	      elsif (0x00100104 == $self->{Chunks}[0][0])
	      {
		$self->{PrintableAXML} .= sprintf "Text -" . sprintf "%#08x\n",$self->{Chunks}[0][0];
		my @CurrentChunk = shift @{$self->{Chunks}}; 
		$self->{Offset} += $CurrentChunk[0][1];
		last;
	      }
	      else
	      {
		$self->{PrintableAXML} .= sprintf "Unknown Tag -" . sprintf "%#08x\n",$self->{Chunks}[0][0];
		my @CurrentChunk = shift @{$self->{Chunks}}; 
		$self->{Offset} += $CurrentChunk[0][1];
		$count--;
		last;
	      }
	}
}


sub GetStrings
{
	my ($self, $StringTablePointer) = @_;
	
	my @strings;
	
	for(my $n = 0; $n < $self->{StringCount}; $n++, $StringTablePointer += 4)	
	{
	
		my $TableOffset = $self->{InpF}->get_long($StringTablePointer) + $self->{StringTableOffset};
		my $StringLength = $self->{InpF}->get_word($TableOffset);

		#unicode
		$StringLength *= 2;
#	        #null terminator
#		$StringLength += 2;

		my $StringOffset = $TableOffset + 2;

# 		$strings[$n] = $self->{InpF}->get_string($StringOffset,$StringLength);
		$strings[$n] = $self->{InpF}->u2a($self->{InpF}->get_string($StringOffset,$StringLength));
	}
	
	$self->{Strings} = [@strings];
}



sub GetPermissions
{
	my $self = shift;
	my @Permissions;
	
	for $i ( 0 .. $#{ $self->{Strings} } ) 
	{
	  if ($self->{Strings}[$i] =~ /\.permission\./)
	  {
	      push @Permissions, $self->{Strings}[$i];
	  }
	}
	
	$self->{Permissions} = [@Permissions];
}



sub GetIntents
{

	my $self = shift;
	my @Intents;
	
	for $i ( 0 .. $#{ $self->{Strings} } ) 
	{
	  if ($self->{Strings}[$i] =~ /\.intent\./)
	  {
	      push @Intents, $self->{Strings}[$i];
	  }
	}
	
	$self->{Intents} = [@Intents];

}






sub DumpStrings
{
	my $self = shift;
	
	for $i ( 0 .. $#{ $self->{Strings} } ) 
	{
		print "$self->{Strings}[$i]\n";
	}

	
}

sub DumpPermissions
{
	my $self = shift;
	
	unless($self->{Permissions}[0])
	{
		print "No permissions requested.\n";
		return;	
	}
	
	for $i ( 0 .. $#{ $self->{Permissions} } ) 
	{
		print "$self->{Permissions}[$i]\n";
	}

	
}


sub DumpIntents
{
	my $self = shift;
	
	for $i ( 0 .. $#{ $self->{Intents} } ) 
	{
		print "$self->{Intents}[$i]\n";
	}
	
}


sub DisplayPrintableAXML
{
	my $self = shift;
	
	print $self->{PrintableAXML};

}

1;																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																														
