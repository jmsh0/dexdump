package DumpLib;

sub new ()
{ 
  my ($this,$fname,$options) = @_;
  my $class = ref($this) || $this; 
  my $self = {}; 
  
  if (ref($fname) eq "GLOB")
  {
  	$self->{FH} = $fname;
  }
  else
  {
	open my $fh,"$fname" or die " Cannot open $fname\n";
	binmode $fh;
	$self->{FH} = $fh;
  }

  bless $self, $class;
}


sub get_byte 
{
  my ($self,$offset) = @_;
  my $temp;
  sysseek $self->{FH},$offset,0;
  sysread $self->{FH},$temp,1;
  return ord($temp);
}

sub get_word {
  my ($self,$offset) = @_;
  my $temp;
  sysseek $self->{FH},$offset,0;
  sysread $self->{FH},$temp,2;
  return unpack "v", $temp;
}

sub get_word_BE {
  my ($self,$offset) = @_;
  my $temp;
  sysseek $self->{FH},$offset,0;
  sysread $self->{FH},$temp,2;
  return unpack "n", $temp;
}

sub get_long {
  my ($self,$offset) = @_;
  my $temp;
  sysseek $self->{FH},$offset,0;
  sysread $self->{FH},$temp,4;
  return unpack "V", $temp;
}

sub get_long_BE {
  my ($self,$offset) = @_;
  my $offset = shift;
  my $temp;
  sysseek $self->{FH},$offset,0;
  sysread $self->{FH},$temp,4;
  return unpack "N", $temp;
}

sub get_string 
{
  my ($self,$offset,$length) = @_;
  my $temp;
  sysseek $self->{FH},$offset,0;
  sysread $self->{FH},$temp,$length;
  return $temp;
}

sub get_stringL
{
  my ($self,$offset) = @_;
  my ($temp,$length);
  
  $length = $self->get_uleb128(\$offset);
    
  sysseek $self->{FH},$offset,0;
  sysread $self->{FH},$temp,$length;
  return $temp;
}


sub get_chunk {
  my ($self,$offset,$length) = @_;
  my $temp;
  sysseek $self->{FH},$offset,0;
  sysread $self->{FH},$temp,$length;
  return $temp;
}

sub get_uleb128 
{
	
	my ($self,$offset) = @_;
	
	my $temp;
	my($currByte,$currByteffset);
	
	while(1) 
	{
	  $currByte = $self->get_byte($$offset); $$offset++;
	  $temp |= (($currByte & 0x7f) << $currByteffset);
	  if (($currByte >> 7) == 0)
	  {
	    last;
	  }
	  $currByteffset += 7;
	}
    
    return $temp;
	
}




1;