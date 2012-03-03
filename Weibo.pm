=pod

=encoding UTF-8

=head1 NAME

Weibo - Sina Weibo OAuth 1.0a Wrapper

=cut

package Weibo;

use strict 'vars';
use warnings;

=head1 VERSION

VERSION - 1.0

=cut

our $VERSION = "1.0";
$VERSION = eval { $VERSION };

=head1 REQUIRE

LWP::UserAgent HTTP::Request Digest::HMAC_SHA1

=cut

sub BEGIN {
    require LWP::UserAgent;
    require HTTP::Request;
    require Digest::HMAC_SHA1;
}

=head1 NAMESPACES

模块中包含如下 namespaces 用来简化 OAuth 过程。

=over 4

=item OAuthToken

OAuthToken 用来解析网页返回的 token 字符串。

    my $resp  = LWP::UserAgent->new()->request('GET', 'http://baidu.com');
    my $token = OAuthToken::from_string($resp->{_content});

=cut

package OAuthToken;

sub new {
    my $class = 'OAuthToken';
    my ($token, $secret) = @_;
    my $self  = {
        key   =>    $token,
        secret=>    $secret,
    };
    bless $self, $class;
}

sub from_string {
    my $str    = shift;
    use CGI;
    my $params = CGI->new($str);
    my ($token, $secret) = (
        $params->param('oauth_token'),
        $params->param('oauth_token_secret'),
    );
    my $self   = &new($token, $secret);
    return $self;
}

sub token {
    my $self = shift;
    return $self->{key};
}

sub secret {
    my $self = shift;
    return $self->{secret};
}

=item OAuthConsumer

OAuthConsumer 用来实例化 token 对。

    my $consumer = OAuthConsumer->new(
        {consumer_token=>'xxx',consumer_secret=>'xxx'}
    );

=cut

#---------------------------------------------------
package OAuthConsumer;

sub new {
    my $class = shift;
    my $token = shift;
    bless $token, $class;
}

sub token {
    my $self = shift;
    return $self->{consumer_token};
}

sub secret {
    my $self = shift;
    return $self->{consumer_secret};
}
#---------------------------------------------------

=item OAuthSignatureMethod_HMAC_SHA1

OAuthSignatureMethod_HMAC_SHA1 用来初始化 HMAC_SHA1 方法。这里用到了 Digest::HMAC_SHA1 包和 MIME::Base64 包。
后期通过继承 OAuthSignatureMethod 来拓展其他加密算法。

    my $signature = OAuthSignatureMethod_HMAC_SHA1->new();

=cut

#-------------------------------------------------------------
package OAuthSignatureMethod;
my $not_implemented = "NotImplementedError";
sub get_name { $not_implemented }
sub build_signature_base_string { $not_implemented }
sub build_signature { $not_implemented }
sub check_signature {
    my $self = shift;
    my ($oauth_request, $consumer, $token, $signature) = @_;
    my $build = $self->build_signature(
                    $oauth_request,
                    $consumer,
                    $token,
    );
    return $build == $signature;
}

package OAuthSignatureMethod_HMAC_SHA1;
use base qw/OAuthSignatureMethod/;
sub escape {
    use URI::Escape;
    return uri_escape($_[0]);
}
sub new { 
    my $class = shift;
    my $self  = {};
    bless $self, $class;
}
sub get_name { "HMAC-SHA1" }
sub build_signature_base_string {
    my $self = shift;
    my ($oauth_request, $consumer, $token) = @_;
    
    my @sig = (
        escape($oauth_request->get_normalized_http_method),
        escape($oauth_request->get_normalized_http_url),
        escape($oauth_request->get_normalized_parameters),
    );
    my $key = escape($consumer->secret) . "&";
    $key = $key . escape($token->secret) if defined $token;
    
    my $raw = join('&', @sig);
    return [$key, $raw];
}
sub build_signature {
    my $self = shift;
    my $ref  = $self->build_signature_base_string(@_);
    
    use Digest::HMAC_SHA1;
    use MIME::Base64;

    my $hmac = Digest::HMAC_SHA1->new($ref->[0]);
    $hmac->add($ref->[1]);
    return encode_base64($hmac->digest, '');
}
#-----------------------------------------------------------------------

=item OAuthRequest

OAuthRequest 用来封装各种 OAuth 请求并生成相应的 header, url 来供进一步请求。

    my $req  = OAuthRequest::from_consumer_and_token(
        $self->{_consumer},$url);
    $req->sign_request(
        $self->{_signature},
        $self->{_consumer}
    );
    my $header = $req->to_header;

=cut

package OAuthRequest;
sub escape {
    use URI::Escape;
    return uri_escape(@_);
}
sub new {
    my $class = 'OAuthRequest';
    my ($http_method, $http_url, $parameters) = @_;
    my $self  = {
        http_method     =>  $http_method,
        http_url        =>  $http_url,
        parameters      =>  defined($parameters)?$parameters:{},
    };
    bless $self, $class;
}
sub from_consumer_and_token {
    my ($consumer, $http_url, $token, $params) = @_;
    my $default  = {
        'oauth_consumer_key'    =>  $consumer->token,
        'oauth_timestamp'       =>  int(time),
        'oauth_nonce'           =>  int( rand(2**32)),
        'oauth_version'         =>  "1.0",
    };
    $default->{oauth_token}    = $token->token if defined $token;
    $default->{oauth_verifier} = $params->{PIN} if defined $params->{PIN};
    my $http_method = 'GET';
    $http_method    = $params->{method} if defined $params->{method};

    my $self = &new($http_method, $http_url);
    $self->{parameters} = $default;
    return $self;
}
sub from_token_and_callback {
    my ($token, $url, $callback)  = @_;
    my $parameters                = {};
    $parameters->{oauth_token}    = $token->token;
    $parameters->{oauth_callback} = $callback if defined $callback;
    my $self = &new('GET', $url, $parameters);
    return $self;
}
sub sign_request {
    my $self = shift;
    my ($sign_method, $consumer, $token) = @_;
    $self->{parameters}->{oauth_signature_method} = $sign_method->get_name();
    $self->{parameters}->{oauth_signature} = escape($sign_method->build_signature(
        $self, $consumer, $token));
}
sub to_header {
    my $self        = shift;
    my $auth_header = 'OAuth realm=""';
    if(not defined($self->{parameters}->{oauth_verifier})) {
    $auth_header = $auth_header . ", oauth_nonce=\""
                 . $self->{parameters}->{oauth_nonce} . "\", "
                 . "oauth_timestamp=\""
                 . $self->{parameters}->{oauth_timestamp} . "\", "
                 . "oauth_consumer_key=\""
                 . $self->{parameters}->{oauth_consumer_key} . "\", "
                 . "oauth_signature_method=\""
                 . $self->{parameters}->{oauth_signature_method} . "\", "
                 . "oauth_version=\""
                 . $self->{parameters}->{oauth_version} . "\", "
                 . "oauth_signature=\""
                 . $self->{parameters}->{oauth_signature} . "\"";
    } else {
    $auth_header = $auth_header . ", oauth_nonce=\""
                 . $self->{parameters}->{oauth_nonce} . "\", "
                 . "oauth_timestamp=\""
                 . $self->{parameters}->{oauth_timestamp} . "\", "
                 . "oauth_signature_method=\""
                 . $self->{parameters}->{oauth_signature_method} . "\", "
                 . "oauth_consumer_key=\""
                 . $self->{parameters}->{oauth_consumer_key} . "\", "
                 . "oauth_verifier=\""
                 . $self->{parameters}->{oauth_verifier} . "\", "
                 . "oauth_version=\""
                 . $self->{parameters}->{oauth_version} . "\", "
                 . "oauth_token=\""
                 . $self->{parameters}->{oauth_token} . "\", "
                 . "oauth_signature=\""
                 . $self->{parameters}->{oauth_signature} . "\"";   
    }
    return [
            'Authorization', $auth_header,
           ];
}
sub to_postdata {
    my $self   = shift;
    my %params = ();
    foreach my $k (keys %{$self->{parameters}}) {
        $params{escape($k)} = escape($self->{parameters}->{$k});
    }
    return join('&', map { $_ . "=" . $params{$_}}
                         keys %params);
}
sub to_url {
    my $self = shift;
    return $self->get_normalized_http_url . "?" . $self->to_postdata;
}
sub get_normalized_parameters {
    my $self = shift;
    delete $self->{parameters}->{oauth_signature}
        if exists $self->{parameters}->{oauth_signature};
    my %params = ();
    foreach my $k (keys $self->{parameters}) {
        $params{escape($k)} = escape($self->{parameters}->{$k});
    }
    my @keys = sort keys %params; 
    return join("&", map {$_ . "=" . $params{$_} } @keys);
}
sub get_normalized_http_method {
    my $self = shift;
    return uc $self->{http_method};
}
sub get_normalized_http_url {
    my $self = shift;
    return $self->{http_url};
}
#-----------------------------------------------------------------------

=item OAuthHandler

OAuthHandler 是整个 OAuth 过程中的主句柄。

    my $hdl = OAuthHandler({consumer_token=>'xx',consumer_secret=>'xx'});

=cut

package OAuthHandler;
my $base = "http://api.t.sina.com.cn/oauth/";
my $urls = {
    request_url     => $base . "request_token",
    auth_url        => $base . "authorize",
    access_url      => $base . "access_token",
};

sub new {
    my $class = shift;
    my $self  = {
        _consumer       =>  OAuthConsumer->new(@_),
        _sigmethod      =>  OAuthSignatureMethod_HMAC_SHA1->new(),
        request_token   =>  undef,
        access_token    =>  undef,
    };
    bless $self, $class;
}

sub get_request_token {
    my $self = shift; 
    my $url  = $urls->{request_url};
    my $req  = OAuthRequest::from_consumer_and_token(
        $self->{_consumer},$url);
    $req->sign_request(
        $self->{_sigmethod},
        $self->{_consumer}
    );
    my $header = $req->to_header;
    use LWP::UserAgent;
    use HTTP::Request;
    my $r = HTTP::Request->new(
        'GET',
        $url,
       $header
    );
    my $agent = LWP::UserAgent->new();
    my $resp  = $agent->request($r);
    return OAuthToken::from_string($resp->{_content});
}

sub get_authorization_url {
    my $self = shift;
    $self->{request_token} = $self->get_request_token;
    my $url  = $urls->{auth_url};
    my $req  = OAuthRequest::from_token_and_callback(
                 $self->{request_token},
                 $url
    );
    return $req->to_url;
}

sub get_access_token {
    my $self = shift;
    my $pin  = shift;
    my $url  = $urls->{access_url};
    my $req  = OAuthRequest::from_consumer_and_token(
                $self->{_consumer},
                $url,
                $self->{request_token},
                {PIN=>$pin},
    );
    $req->sign_request(
        $self->{_sigmethod},
        $self->{_consumer},
        $self->{request_token}
    );
    use LWP::UserAgent;
    use HTTP::Request;
    my $r     = HTTP::Request->new(
                 'GET',
                 $url,
                 $req->to_header
    );
    print $req->to_header->[1],"\n";
    my $agent = LWP::UserAgent->new();
    my $resp  = $agent->request($r);
    print $resp->{_content},"\n";
    my $token = OAuthToken::from_string($resp->{_content});
    $self->{access_token} = $token;
    return $token;
}

sub set_access_token {
    my $self  = shift;
    my $token = shift;
    $self->{access_token} = $token;
}

sub fetch {
    my $self = shift;
    my ($api, $http_method, $params) = @_;
    my $req  = undef;

    my $url  = $api->get_url;
    if (uc $http_method eq 'GET') {
        $url .= '?' if defined $params;
        foreach my $k (keys %{$params}) {
            $url = $url . '&' unless substr $url,-1 eq '?';
            $url = $url . $k . '=' . $params->{$k};
        }
        print "GET API: $url\n";
        $req = OAuthRequest::from_consumer_and_token(
                    $self->{_consumer},
                    $url,
                    $self->{access_token},
        );
    } else {
        $req = OAuthRequest::from_consumer_and_token(
                    $self->{_consumer},
                    $url,
                    $self->{access_token},
                    {
                        method  =>  $http_method,
                        %{$params},
                    }
        );
    }
    
    $req->sign_request(
        $self->{_sigmethod},
        $self->{_consumer},
        $self->{access_token},
    );
    
    use HTTP::Request;
    use LWP::UserAgent;

    my $agent = LWP::UserAgent->new;
    my $r     = HTTP::Request->new(
                    uc $http_method,
                    $req->to_url,
    );
    my $resp  = $agent->request($r);
    print $resp->{_content};
}

=item API

Weibo API Handler

=cut

package API;

our $AUTOLOAD;
my  $base_url = "http://api.weibo.com/2";
my  $api_url  = $base_url;
my  @branches = qw/
        statuses
        emotions
        comments
        users
        friendships
        account
        favourites
        trends
        tags
        register
        suggestions
        remind
        common
        location/;

sub new { bless {}, "API" }

sub AUTOLOAD {
    my $self = shift;
    my $name = $AUTOLOAD;
    $name    =~ s/.*://;
    $api_url = $base_url if grep { $_ eq $name } @branches;
    $api_url = $api_url . "/" . $name;
    return $self;
}

sub get_url { $api_url }

#-------------------------------------------------------------------

1;

=back

=head1 AUTHOR

xiaomo(wxm4ever@gmail.com)

=cut

#-------------------------------

#package main;
#my $consumer_token  = "2986120742";
#my $consumer_secret = "796b90d5a6e3a1cc4d719726f5f99f7d";
#my $access_token    = "c7a7b33fd0d8386591a4611d42dd182b";
#my $access_secret   = "862a8dbfbd846bbd46931dd0d5a90f26";

#my $hdl = OAuthHandler->new({
#    consumer_token  =>  $consumer_token,
#    consumer_secret =>  $consumer_secret,
#});
#print $hdl->get_authorization_url(),"\n";
#my $pin = <>;
#chomp $pin;
#print "PIN: $pin\n";
#$access_token = $hdl->get_access_token($pin);
#my $token = OAuthToken->new($access_token, $access_secret);
#$hdl->set_access_token($token);

__END__
