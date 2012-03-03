use Weibo;
use LWP::UserAgent;
use HTTP::Request;

my $agent = LWP::UserAgent->new;

my $consumer_token  = "2986120742";
my $consumer_secret = "796b90d5a6e3a1cc4d719726f5f99f7d";

my $hdl = OAuthHandler->new({
    consumer_token  =>  $consumer_token,
    consumer_secret =>  $consumer_secret,
});
print $hdl->get_authorization_url, "\n";

my $pin = <>;
chomp $pin;
my $access_token = $hdl->get_access_token($pin);

my $resp = $hdl->fetch(
    API->new->users->show,
    'GET',
    {screen_name=>'DolphinQ'}
);

print $resp->{_content};
