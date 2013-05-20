package AxmlHeuristics;
###############################################################################
# This program is licensed under the GNU Public License, version 3 or later.
# A copy of this license is included in the package as License.txt.
# If it is missing, a copy is available at http://www.gnu.org/copyleft/gpl.html
###############################################################################

sub new 
{ 
  my ($this,$axml) = @_;
  my $class = ref($this) || $this; 
  my $self = {}; 
  bless $self, $class;
  
  $self->{AXML} = $axml;
  
  return $self; 
  
}



sub Run
{

  my $self = shift;

  $self->SuspiciousPermisions;

}



sub SuspiciousPermisions
{

	my $self = shift;
	
	my %suspicousPermissions = 
	(
	'android.permission.READ_CONTACTS' => 0x1,
	'android.permission.ACCESS_COARSE_LOCATION' => 0x1,
	'android.permission.ACCESS_FINE_LOCATION' => 0x1,
	'android.permission.ACCESS_NETWORK_STATE' => 0x1,
	'android.permission.AUTHENTICATE_ACCOUNTS' => 0x1,
	'android.permission.BROADCAST_SMS' => 0x1,
	'android.permission.BROADCAST_WAP_PUSH' => 0x1,
	'android.permission.CALL_PHONE' => 0x1,
	'android.permission.CALL_PRIVILEDGED' => 0x1,
	'android.permission.CAMERA' => 0x1,
	'android.permission.CHANGE_COMPONENT_ENABLED_STATE' => 0x1,
	'android.permission.CHANGE_NETWORK_STATE' => 0x1,
	'android.permission.CHANGE_WIFI_STATE' => 0x1,
	'android.permission.CLEAR_APP_USERS_DATA' => 0x1,
	'android.permission.CONTROL_LOCATION_UPDATES' => 0x1,
	'android.permission.DISABLE_KEYGUARD' => 0x1,
	'android.permission.GET_ACCOUNTS' => 0x1,
	'android.permission.GET_TASKS' => 0x1,
	'android.permission.INJECT_EVENTS' => 0x1,
	'android.permission.INSTALL_LOCATION_PROVIDER' => 0x1,
	'android.permission.INSTALL_PACKAGES' => 0x1,
	'android.permission.INTERNET' => 0x1,
	'android.permission.KILL_BACKGROUND_PROCESSES' => 0x1,
	'android.permission.MANAGE_ACCOUNTS' => 0x1,
	'android.permission.PERSISTENT_ACTIVITY' => 0x1,
	'android.permission.PROCESS_OUTGOING_CALLS' => 0x1,
	'android.permission.READ_SMS' => 0x1,
	'android.permission.READ_SOCIAL_STREAM' => 0x1,
	'android.permission.RECEIVE_SMS' => 0x1,
	'android.permission.RECEIVE_MMS' => 0x1,
	'android.permission.RECEIVE_WAP_PUSH' => 0x1,
	'android.permission.SEND_SMS' => 0x1,
	'android.permission.USE_CREDENTIALS' => 0x1,
	'android.permission.WRITE_SETTINGS' => 0x1,
	'android.permission.WRITE_SMS' => 0x1,
	'android.permission.WRITE_SOCIAL_STREAM' => 0x1,
	'android.permission.RECEIVE_BOOT_COMPLETED' => 0x1
	);
	
	unless($self->{AXML}->{Permissions}[0])
	{
		print "No permissions requested.\n";
		return;	
	}
	
	
	
	for $i ( 0 .. $#{ $self->{AXML}->{Permissions} } ) 
	{
		if ($suspicousPermissions{$self->{AXML}->{Permissions}[$i]} )
		{
		  push @suspPerms,$self->{AXML}->{Permissions}[$i];
		}
	}

	if($suspPerms[0])
	{
	  print <<PERM;
---------------------|
Suspcious Permissions|
---------------------|
PERM
	  
	  for my $perms (@suspPerms)
	  {
	    print "$perms\n";
	  }
	  
	}

}



1;