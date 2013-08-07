package AxmlHeuristics;
###############################################################################
# This program is licensed under the GNU Public License, version 3 or later.
# A copy of this license is included in the package as License.txt.
# If it is missing, a copy is available at http://www.gnu.org/copyleft/gpl.html
###############################################################################

use Carp;

sub new 
{ 
  my ($this,$axml,$tempfh) = @_;
  my $class = ref($this) || $this; 
  my $self = {}; 
  bless $self, $class;
  
  
   
  $self->{AXML} = $axml;
  $self->{apkFH} = $tempfh;
  
  return $self; 
  
}



sub Run
{

  my $self = shift;
  
  $self->BlacklistCertificates;
  $self->SuspiciousPermisions;

}


sub BlacklistCertificates
{
    
	my $self = shift;

	my %BlacklistedCerts = 
	(
	'cef1c2b6f3bba9f029615d1a1de77f9d' => "Android/Ackposts Variant",
	'6ddc4d9900f06406b3637aa2c1efc4b1' => "Android/Actrack Variant",
	'49a5fbef2ef21044eac1410f927443df' => "Android/AdWoLeaker Variant",
	'41a33f015c219cf290e23165315bc31a' => "Android/AdWpxLeaker Variant",
	'aba334976781268e16d070fc169898c0' => "Android/AdWpxLeaker Variant",
	'db34c887c256db402d8361c6a5298588' => "Android/AnitTool Variant",
	'efe2e98f3da79f17b281b8241e75a51c' => "Android/AnitTool Variant",
	'e804b52d1ca20eebd78a2b8dbe22242d' => "Android/Anserver Variant",
	'713f5e182a456452a09908e70cd52d38' => "Android/AnZhor7 Variant",
	'f7e51223d3c0daf9f6211dae9cad8cbb' => "Android/ApkMon Variant",
	'80f28bbbd5c6406eca8a0f59744b6048' => "Android/Apkqu Variant",
	'76a2ecdae5e07776000dd32373f78d8c' => "Android/AppHnd Variant",
	'ddb23d8b2429601769a1e83cf9578018' => "Android/AppHnd Variant",
	'f246306062c43bb0a45ad6076346bbe6' => "Android/AppHnd Variant",
	'43006ed2b2ec9782f6a7509f5d404a6d' => "Android/AreSpy Variant",
	'41a33f015c219cf290e23165315bc31a' => "Android/Arspam Variant",
	'75122e6e1ee40c0c45fb11a14d4c512c' => "Android/BackReg Variant",
	'4cb9641b1099f0377de086a2cc693d37' => "Android/Backscript Variant",
	'4dcaef9e75af86211073535b9a0a2a38' => "Android/BaseBridge Variant",
	'b8fbc9962e0ffce8e712133258dd4d8c' => "Android/BaseBridge Variant",
	'38f59b63580b2b131c069f3d25911323' => "Android/Bgyoulu Variant",
	'41a33f015c219cf290e23165315bc31a' => "Android/Bgyoulu Variant",
	'fc289aab28dfd29bcee939a74792a8d4' => "Android/BookFri Variant",
	'f76283b1cbfc6fc6d6970f2cd86eae84' => "Android/Carotap Variant",
	'bcbfec7b61e81f7ead06f6274ec27d3a' => "Android/CIQ Variant",
	'dd0f3cbf4ef72724827c70dffd9629eb' => "Android/CIQ Variant",
	'706ae92e0e774612990cccfa6842a459' => "Android/Citmo Variant",
	'322178f456e17aad26021c383cd0d299' => "Android/Coolpaperleak Variant",
	'9598d82e9cad7bc089dd9746a6f78a0d' => "Android/Crusewin Variant",
	'2f79a03a166faf8fd644e4ecb46249b6' => "Android/Dialer Variant",
	'8007d3dc449c7a8f30c2bfbb8e20990f' => "Android/DIYAds Variant",
	'8007d3dc449c7a8f30c2bfbb8e20990f' => "Android/DIYDoS Variant",
	'583e78e49d8ab2b6dcf92c7153d80835' => "Android/DougaLeaker Variant",
	'41a33f015c219cf290e23165315bc31a' => "Android/Drad Variant",
	'c9ec8b658ba6291e1aca4b1ec6e3822a' => "Android/Drad Variant",
	'627caf36e4f29931f6496b1fbcd3d625' => "Android/DrddreamLite Variant",
	'88224e170564459762cec8057fb2d2aa' => "Android/DrddreamLite Variant",
	'8bc378e2c1689828b67b541c5baaa74c' => "Android/DrddreamLite Variant",
	'380f5bac84d400fba2a93f28f5729299' => "Android/DrdDreamLite Variant",
	'41a33f015c219cf290e23165315bc31a' => "Android/DrdDreamLite Variant",
	'627caf36e4f29931f6496b1fbcd3d625' => "Android/DrdDreamLite Variant",
	'65c3ca2cb054596ebebc3c28adb1f0f4' => "Android/DrdDreamLite Variant",
	'6bccbb06efb9d71bd478b7445b038eb6' => "Android/DrdDreamLite Variant",
	'8485dd4c74fec270f800da9f2022f9be' => "Android/DrdDreamLite Variant",
	'88224e170564459762cec8057fb2d2aa' => "Android/DrdDreamLite Variant",
	'a3ddebced21bbc3d156e288cd5df5a07' => "Android/DrdDreamLite Variant",
	'abe7f528e7fc0995a3c61395e325fb14' => "Android/DrdDreamLite Variant",
	'34434e246cae03d5350293a410d247e0' => "Android/DrdDream Variant",
	'8ffe83fbada463c4c52c8ae83d43fb8d' => "Android/DrdLive Variant",
	'325eabea3ab3a84482c73bb111e0ba8a' => "Android/DroidDeluxe Variant",
	'0be5c1fc9b40c5b9ef079217230b1418' => "Android/DroidKungFu Variant",
	'1b67a43f6ef71dd803a3ee17a7741275' => "Android/DroidKungFu Variant",
	'49a5fbef2ef21044eac1410f927443df' => "Android/DroidKungFu Variant",
	'a936a1cc34102c98c6036383b45c596b' => "Android/DroidKungFu Variant",
	'd438b789f9442f70e06818785265fe2e' => "Android/DroidKungFu Variant",
	'f98f12c0a3fdcfdada5a5364ceeab91e' => "Android/DroidKungFu Variant",
	'cc1ec1700cf95add6829df7ba530eb53' => "Android/DropDialer Variant",
	'e3ae6c5571ee4d9d34aefc9fac74ad43' => "Android/Ecardgrabber Variant",
	'3eabb1178c0df955fb988e5ac615f173' => "Android/Ecobatry Variant",
	'cc0911ac14fdeacd0f4cecb1d0d354ee' => "Android/Enesoluty Variant",
	'f5c7e01f92e809e8e9ae0fdf09217226' => "Android/EvoRoot Variant",
	'1c6dcb4578b726814684794065acc0dc' => "Android/Exprespam Variant",
	'75af29e9c5bc540e2bdcd27bf417bfc1' => "Android/Exprespam Variant",
	'6fd023a3e1e016d17de5791675d83282' => "Android/ExtensionDropper Variant",
	'6fd023a3e1e016d17de5791675d83282' => "Android/Extension Variant",
	'4ceced8e3c0d530c553a00054b19abbc' => "Android/ExynosToor Variant",
	'0d59cdf5bbd89ddee4633c1a81539ba9' => "Android/FaceNiff Variant",
	'713f5e182a456452a09908e70cd52d38' => "Android/FakeAngry Variant",
	'b964218364042cfaf76bd0d8262980c7' => "Android/FakeBapp Variant",
	'0baaee3b825cbd200240bc334f7c5578' => "Android/FakeBrowser Variant",
	'2f139c4067698d089292dba0e1879e6d' => "Android/FakeGame Variant",
	'f98244ae15880ca40d9479a27d3cb8ee' => "Android/FakeGuard Variant",
	'15c0001dbb586f13d19c969830d71409' => "Android/FakeInstaller Variant",
	'1cfbb69115b1c32e3aa9f0f1fde2325e' => "Android/FakeInstaller Variant",
	'1d6dbf499933c263a669be8e5ba46acc' => "Android/FakeInstaller Variant",
	'29208f4e89a4c9b0da00412599fa9ce3' => "Android/FakeInstaller Variant",
	'292117b745736dd7d08e0bf10ddf0fe9' => "Android/FakeInstaller Variant",
	'3d5dc83344922865561ad4ecf045904b' => "Android/FakeInstaller Variant",
	'674ee7b772a1529d120259163f607887' => "Android/FakeInstaller Variant",
	'6832ee5054a7db4fa99245adc3ef7e09' => "Android/FakeInstaller Variant",
	'7edc27a4c06e4d93c54a2895b2f59b90' => "Android/FakeInstaller Variant",
	'9fa3e06fae1d0e99acd0e500f4bd9492' => "Android/FakeInstaller Variant",
	'5f8183e00c46ff6f24697ada30571715' => "Android/Fakelash Variant",
	'adbc7e7ead2185ba98202f7b63ab8fb1' => "Android/FakeLookout Variant",
	'afd1b7381ddaf3fc88e3587c256c1802' => "Android/FakeMarket Variant",
	'348060f7e82b0598dffb4b6a16c59222' => "Android/FakePlayer Variant",
	'84d4e01aca733ff706df83ffd61408f2' => "Android/FakeSecSuit Variant",
	'1556856c0435aa4753f25d7e3b62c894' => "Android/FakeSecTool Variant",
	'e3f00df90f42793b3b493919ffc1405d' => "Android/FakeToken Variant",
	'41a33f015c219cf290e23165315bc31a' => "Android/FakeUpdates Variant",
	'4cb9641b1099f0377de086a2cc693d37' => "Android/FakeUpdates Variant",
	'8a531c56b5d9096e53c87e6ccf6351e7' => "Android/FakeUpdates Variant",
	'e21e7b0f70d4f2e3194d3f2c6e8eba2f' => "Android/FakeUpdates Variant",
	'd3cb1311475e845c9d9dffa459924362' => "Android/FinSpy Variant",
	'8007d3dc449c7a8f30c2bfbb8e20990f' => "Android/Fladstep Variant",
	'41a33f015c219cf290e23165315bc31a' => "Android/FlashRec Variant",
	'7eaef1a3162a467a1574b9fcbf341dc6' => "Android/FlashRec Variant",
	'a3175a545406a389578e66e777325cea' => "Android/FlashRec Variant",
	'b1b3cbcef7fbbd530ac68aab16d662b6' => "Android/FndNCll Variant",
	'41a33f015c219cf290e23165315bc31a' => "Android/Foncy Variant",
	'743b14c03a8c1d3343f8bf6f90ff1686' => "Android/FrictSpy Variant",
	'b602c57ba48b55843e9e9b0135ff4c10' => "Android/FrictSpy Variant",
	'fb73cb7123b8da6e37951c9d602473e6' => "Android/Frogonal Variant",
	'ace598d1da3760f19102ef9e20ca2288' => "Android/Frutk Variant",
	'84d678b117301a2eca44075454fb3554' => "Android/FunsBot Variant",
	'41a33f015c219cf290e23165315bc31a' => "Android/GamexDropper Variant",
	'41a33f015c219cf290e23165315bc31a' => "Android/Geinimi Variant",
	'4dcaef9e75af86211073535b9a0a2a38' => "Android/Generic Variant",
	'bdda4a458bc581cca7812a3078ec35a4' => "Android/Generic Variant",
	'de0f7bb6e9bc5ab455785472b7619b1e' => "Android/GGeeGame Variant",
	'bdda4a458bc581cca7812a3078ec35a4' => "Android/GGTracker Variant",
	'5be8e079f43aa8d8dba552020446cb93' => "Android/GinMaster Variant",
	'97d217a880f75aaa8214c21e2d0d0cbf' => "Android/GinMaster Variant",
	'a55d67a11808571b199f05f98c5bdc76' => "Android/GinMaster Variant",
	'41a33f015c219cf290e23165315bc31a' => "Android/GoldDream Variant",
	'a3846856fefd935f608d650526af46af' => "Android/GoldDream Variant",
	'31215967f93dfac0420e2a575e699d7e' => "Android/GoldenEagle Variant",
	'2f1573ba6fd597a22d26236c44f45519' => "Android/GoneSixty Variant",
	'6adea976e927db4517d2f685beee4378' => "Android/GoneSixty Variant",
	'd058e4399d78772476fb283655a100fe' => "Android/GoneSixty Variant",
	'd6a835f67da2f94e04810fb7a0ec0e09' => "Android/GoneSixty Variant",
	'fed0eb3b0f1efafcfcefac1b71337442' => "Android/GoneSixty Variant",
	'a066d70dea99657ea4448c294b698f23' => "Android/GpsNake Variant",
	'69a05d89e9ad481b58d5cd19e0737930' => "Android/Gugespy Variant",
	'bf3cfb817cba9aef5159ebb31e5b89c1' => "Android/HippoSMS Variant",
	'41a33f015c219cf290e23165315bc31a' => "Android/Hnway Variant",
	'18f13e78832f8d057bc754e182013bf9' => "Android/IMWebViewer Variant",
	'b8fbc9962e0ffce8e712133258dd4d8c' => "Android/InstBBridge Variant",
	'3144cd9330b55d0b623c0db4a699143a' => "Android/Jifake Variant",
	'bc0ea41cd30d3c46d5e07932623e5a76' => "Android/Jifake Variant",
	'1b4fb20b133839c0eba49ac219af964a' => "Android/Jmsonez Variant",
	'b8a97f804441ec10c86a281d66cb56b1' => "Android/Jmsonez Variant",
	'dd9c76667874fbac6c946ffd799adbc4' => "Android/Jmsonez Variant",
	'29c01d6a056e708d69552c9e82ef449c' => "Android/Kituri Variant",
	'48af9b9385bfe5845baefb3f82fc13cf' => "Android/LdBolt Variant",
	'52cd5694dca798103ef09d8157f2e21b' => "Android/LdBolt Variant",
	'7fe3b482ccace8333ff247c069d211f4' => "Android/LdBolt Variant",
	'b0ab860550f678df1d68daca94464ab6' => "Android/LdBolt Variant",
	'e130eaff5767b5e6af17ca1a9dc8b6d4' => "Android/LdBolt Variant",
	'0c9673527a09e5599f02e12080ff9024' => "Android/Lemon Variant",
	'e89f564c92f9d5687012450c3bd3d057' => "Android/LoggerKid Variant",
	'f055dc4e6bf6c4baa8241b6d3b6f2fb2' => "Android/Logkare Variant",
	'680525dbdede2238165d9ecddc81dbf2' => "Android/Loozfon Variant",
	'5565dbe191407ba594c38fa6107a8605' => "Android/LoveTrp Variant",
	'944db3fae7fd56380dc4d3ecfbb41db5' => "Android/Maistealer Variant",
	'f1d5a6c2eec4e28a569c276de71d7d06' => "Android/Malebook Variant",
	'41a33f015c219cf290e23165315bc31a' => "Android/Mania Variant",
	'57c4704051bd479db96b8578d6428fd5' => "Android/MarketPay Variant",
	'af9f86ce37ccd03ecd4f488bceb629e9' => "Android/Mavms Variant",
	'98a47131220b6cfbcc75e13250390497' => "Android/Mobispy Variant",
	'b4762fcb7fb0f80030a37d0429e5deea' => "Android/Mobispy Variant",
	'592347322598aa3a654bf797dd9a8625' => "Android/Mobspy Variant",
	'62015aee42f7d787f711f4da7290621c' => "Android/MobTracker Variant",
	'cde6a52f22867a120454d79de367998b' => "Android/MobTracker Variant",
	'41a33f015c219cf290e23165315bc31a' => "Android/Moghava Variant",
	'a066d70dea99657ea4448c294b698f23' => "Android/MoneyFone Variant",
	'57c4704051bd479db96b8578d6428fd5' => "Android/Morepacks Variant",
	'20e09e04c0127bcf0eabcd933b36cdee' => "Android/Nandrobox Variant",
	'b8c47a2fc3db3fa5250dbd5f1270ee5c' => "Android/Nautaj Variant",
	'41a33f015c219cf290e23165315bc31a' => "Android/Netisend Variant",
	'17b6ab05fddb8103d9f27a10fd7061d8' => "Android/NickiSpy Variant",
	'536c319c3578ac4520b057d07d8d201d' => "Android/NickiSpy Variant",
	'd14c5f8f973132eab1daaff78ccbb75e' => "Android/NotCompatible Variant",
	'27917b3bfc2c513e082ae4d3531b3d68' => "Android/Nproplap Variant",
	'a99b4406afaa2064226caa4483e2d859' => "Android/Nyearleaker Variant",
	'0b64942189840dfca24c7844059a5424' => "Android/OneClickFraud Variant",
	'32eea8b6d450cb4e4b20f347dd0fbfc6' => "Android/OneClickFraud Variant",
	'678915e4b1fc25091c52177b53b3d1aa' => "Android/OneClickFraud Variant",
	'6ba8a16e49ff743566d9cffc8430b60e' => "Android/OneClickFraud Variant",
	'7459df4a3aef4950b5ff15020232d90f' => "Android/OneClickFraud Variant",
	'8211d7ced2d89aac0d2f329df28c1d15' => "Android/OneClickFraud Variant",
	'86af2e881d0aa722a8ed557801a7d3f0' => "Android/OneClickFraud Variant",
	'8d85221ea84c93bfd0930845746f6315' => "Android/OneClickFraud Variant",
	'e12632fb0a320d14c7f4b85218777793' => "Android/OneClickFraud Variant",
	'e26d422830e11a37d83eb98648bc3fc6' => "Android/OneClickFraud Variant",
	'081c4bd4d16f972ad2dd1eddd9d4e08e' => "Android/Ozotshielder Variant",
	'fbaeeb9d86d3d908e2d14735b8863afc' => "Android/PBL Variant",
	'370f4b82ba35a90849498bf7c7b38865' => "Android/PdaSpy Variant",
	'0c9b44b615d91677f3c5c6422ddf6dfb' => "Android/Pirates Variant",
	'41a33f015c219cf290e23165315bc31a' => "Android/PJApps Variant",
	'9f3d46380afc4949215219a926370245' => "Android/PremiumText Variant",
	'713f5e182a456452a09908e70cd52d38' => "Android/Qicsomos Variant",
	'56a32eb0ff60604c1e89321ddcb79739' => "Android/QieTing Variant",
	'c530db575fb9e337883f86081eb61993' => "Android/qihoo Variant",
	'31c2ed1836988eefce2eeb9b269d50ab' => "Android/QuoteDoor Variant",
	'b804abfc0b43a368575f55eaac9b5cdc' => "Android/RecCaller Variant",
	'4ce9d076a0b03f580d71ec1768871940' => "Android/RootSmart Variant",
	'b0f18d2370596a2deff55caa15026ca5' => "Android/RuFraud Variant",
	'cabe7cb29fe61c4bf6b4d97376a2ffbc' => "Android/RuFraud Variant",
	'cea7c3ef4fd3e5ccaa0e1ff62d3abfd1' => "Android/RuFraud Variant",
	'5dc58d37723dc12b8f098dee41ca2c0a' => "Android/SGSpyAct Variant",
	'5dc58d37723dc12b8f098dee41ca2c0a' => "Android/SGSpyLite Variant",
	'5dc58d37723dc12b8f098dee41ca2c0a' => "Android/SGSpy Variant",
	'f497ca4e1441870ff5328f25271a1b85' => "Android/ShdBreak Variant",
	'5fc46d3429b9aa71bb5b8a4926873dc6' => "Android/Sinuroot Variant",
	'38f59b63580b2b131c069f3d25911323' => "Android/SMSBite Variant",
	'a9a21f2dc05d53a135995b378a5be6f8' => "Android/SMSbomber Variant",
	'd00e20d6c68433c2f369976cccf6154b' => "Android/SmsBomer Variant",
	'6c6ec5258333c1200ba5d23a08a303c6' => "Android/SMSend Variant",
	'e3f00df90f42793b3b493919ffc1405d' => "Android/SMSend Variant",
	'fc044b61704ca90828534d69cf45e41a' => "Android/SMSend Variant",
	'468b2f0c56c13eb1f4d296252ec91c09' => "Android/SMSHider Variant",
	'713f5e182a456452a09908e70cd52d38' => "Android/SMSHider Variant",
	'bb3c2359b69034c21e0e0b3078fa90fa' => "Android/SMSHider Variant",
	'54954273daf73196dc41cee6abeaec9e' => "Android/SmsHowU Variant",
	'6550b35da172980528de2bb65f56cb33' => "Android/Smsilence Variant",
	'50257b86b965fae08c98af59a62ea4cb' => "Android/Smsmecap Variant",
	'156db13fbf21bf114706f607754fad70' => "Android/SmsSpy Variant",
	'fe2c87056fbace1a0470a7fded262c04' => "Android/SMSTrackerCgFinder Variant",
	'c6d5fdb5d41c48c39b7f4a458c351ad1' => "Android/SMSTrack Variant",
	'b804abfc0b43a368575f55eaac9b5cdc' => "Android/SMSTransfer Variant",
	'3805512e939c9e8678baacc8421d7801' => "Android/SMSWatcher Variant",
	'5f667aafccc5a92d1d88fd29a5296bc1' => "Android/SMSzombieDrp Variant",
	'5f667aafccc5a92d1d88fd29a5296bc1' => "Android/SMSzombie Variant",
	'c42f0e01e60e7a7e478ddf60fafdfe46' => "Android/Sngo Variant",
	'37672f9b6f26518d1c4594b544d6122b' => "Android/SpamSold Variant",
	'41a33f015c219cf290e23165315bc31a' => "Android/Spitmo Variant",
	'284b1ef78f37ef99ddfe03e69ccebcee' => "Android/SpyAndroidAgent Variant",
	'2cef91e39d8da49ec609ac6087b0f4cf' => "Android/SpyBubb Variant",
	'3183bd1942df90fde9aebd09addeb566' => "Android/SpyBubb Variant",
	'8a9e09c64c6e102c3520ff50eb7dc4cc' => "Android/SpyBubb Variant",
	'1b6e36765baeac7fbbc79eb14a1a5b8a' => "Android/Spytrack Variant",
	'75485aa516a1c27810153ef8f03100e4' => "Android/Ssucl Variant",
	'41a33f015c219cf290e23165315bc31a' => "Android/SteamyScr Variant",
	'80ce5bd8e5cd96125aa3230af0348c04' => "Android/Steek Variant",
	'f5cf41e5b73061750837600bf2937a88' => "Android/Steek Variant",
	'b806843a0cb464cd95ef70d66d707544' => "Android/StiffWeather Variant",
	'4bbf70a0aacb1eb2a3628f4627b4e7d9' => "Android/Stiniter Variant",
	'62be17d40ecc490d3317d31f545a16b1' => "Android/Sumzand Variant",
	'd7a38b6e89bb5b814d5b6e83505444cf' => "Android/SusetupTool Variant",
	'284b1ef78f37ef99ddfe03e69ccebcee' => "Android/Sxjspy Variant",
	'7b0cd26444b4ca15c2f5474e10fe4e7c' => "Android/Sysecsms Variant",
	'069c93ae58b413de1e2b880e11843d29' => "Android/Tascudap Variant",
	'cb8719bc8c8810bae66b16b989039173' => "Android/Tcent Variant",
	'93c41d40c350530429f2a22784e3fc23' => "Android/Tetus Variant",
	'3d1555512a357b2f8057e34c8519307a' => "Android/ToorKing Variant",
	'6e5a6f32cdd7135f93416360716a61a8' => "Android/Toplank Variant",
	'8b19d3f596412b0779d1bd93e609ddc4' => "Android/Toplank Variant",
	'8123c50ed0547954f9c488c6e7edf7d9' => "Android/TucySMSDropper Variant",
	'8123c50ed0547954f9c488c6e7edf7d9' => "Android/TucySMS Variant",
	'04f9f79acda4f36679017b12c99c351b' => "Android/Twikabot Variant",
	'd3a468e6634b63aef87f25b54fdbf76d' => "Android/TypStu Variant",
	'975ea019ebcd19c6c0a513127b3af700' => "Android/UpdtKiller Variant",
	'20b4f7c3b6f04c332fc586ac5e3762c1' => "Android/UranaiCall Variant",
	'2fc549355d0337a4829665e617fe6faf' => "Android/Urwhere Variant",
	'41a33f015c219cf290e23165315bc31a' => "Android/VDLoader Variant",
	'54cae0a1f2bffc7e819677f54e4a5202' => "Android/Vidro Variant",
	'3368d317aa6f7aefe64c176426176cb3' => "Android/WalkTxt Variant",
	'745f63b967bc7b86ab1004c0c41c3ca1' => "Android/Wapaxy Variant",
	'dd9c76667874fbac6c946ffd799adbc4' => "Android/Woobooleaker Variant",
	'1beb19523a4573e8a396ee653c82fbf2' => "Android/XanitreSpy Variant",
	'274f1f2e2af0d9a33eb3a380b3c82339' => "Android/XanitreSpy Variant",
	'35dce5a38136314fb9a899a77693d9ff' => "Android/XanitreSpy Variant",
	'897c80716ebf35e9228535a94a21a5c2' => "Android/XanitreSpy Variant",
	'bf31700b316e488637eb104053f0a707' => "Android/XanitreSpy Variant",
	'c20a0f54803e0723da7cf73bac8eccdf' => "Android/XanitreSpy Variant",
	'd5d264f912f3c28435adee9892e2461a' => "Android/XanitreSpy Variant",
	'e720123961fe57b5a7f61aa4e9509275' => "Android/XanitreSpy Variant",
	'fa06dc4cbeeeb3e0a4c7c78564a9f534' => "Android/XanitreSpy Variant",
	'f541e214e9969adfe178808c53fb839f' => "Android/XobSms Variant",
	'886fc757670f906ce9f29dd3c29b91fe' => "Android/YiCha Variant",
	'0c36fa8b046412273b39d8b6af127f00' => "Android/Zitmo Variant",
	'3dda44b3bb62e4a213bf6b58fa2eb74f' => "Android/Zitmo Variant",
	'c6f98833cc867184b69e1c79ad17f084' => "Android/Zitmo Variant"
	);
	
	
	my $zip = Archive::Zip->new($self->{apkFH});
	unless($zip)
	{
		croak "Error opening Zip/APK file.\n";
	}
	my @AndRSA = $zip->membersMatching('.[D|R]SA');

	unless(@AndRSA)
	{
		croak "Invalid APK: Missing <Cert>.RSA\n";	
	}

	
	my $AndRSADir = File::Temp->newdir();

	my $AndRSAfile = File::Temp->new( TEMPLATE => 'tempXXXXX', DIR =>  $AndRSADir->dirname, SUFFIX => '.RSA');

	unless($AndRSA[0]->extractToFileNamed($AndRSAfile->filename) == AZ_OK)
	{
		croak "Unable to extract Cert.RSA.\n";
	}
	my $RSAfn = $AndRSAfile->filename; 
# 	print "\n";

	
	my @md5 = split /  /, `openssl pkcs7 -text -print_certs -inform DER \<$RSAfn|md5sum`;
# 	print "md5 = $md5[0]\n";
	
	if ($BlacklistedCerts{$md5[0]})
	{
	  print <<PERM;
----------------|
Possible Variant|
----------------|
PERM
	
	}
	
	  print "$BlacklistedCerts{$md5[0]}\n";



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
	'android.permission.DELETE_PACKAGES' => 0x1,
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
	'android.permission.RESTART_PACKAGES' => 0x1,
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
	
# 	  if ($self->{options}{v})
# 	  {
	  print <<PERM;
---------------------|
Suspcious Permissions|
---------------------|
PERM
# 	  }
	  
	  for my $perms (@suspPerms)
	  {
	    print "$perms\n";
	  }
	  
	}

}



1;