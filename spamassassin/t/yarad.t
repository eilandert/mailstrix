#!/usr/bin/perl
# Hermetic unit tests for the SpamAssassin Yarad plugin. They need
# Mail::SpamAssassin installed (the plugin `use`s its base class + Logger) plus
# HTTP::Tiny + JSON::PP (core since 5.14), but NO running yarad: http mode is
# driven by a mocked HTTP::Tiny::post, shellout mode by fake yarad-scan scripts.
#
# Run:  prove -v spamassassin/t/yarad.t   (from the repo root, with the plugin
# importable — the CI step adds spamassassin/ to @INC via -I).

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin;

BEGIN {
    eval { require Mail::SpamAssassin::Plugin; 1 }
        or plan skip_all => 'Mail::SpamAssassin not installed';
}

# The plugin file is shipped as spamassassin/Yarad.pm, NOT at the module's @INC
# path (Mail/SpamAssassin/Plugin/Yarad.pm), so load it by file path. Executing it
# defines the Mail::SpamAssassin::Plugin::Yarad package.
require "$FindBin::Bin/../Yarad.pm";

# A bare instance is enough to call the _scan_* helpers: they use only $self
# (for _token), $pms (a plain hashref of cache slots), $conf and the message ref.
my $self = bless {}, 'Mail::SpamAssassin::Plugin::Yarad';

sub fresh_pms { return { yarad_matched => 0, yarad_high => 0, yarad_error => 0, yarad_rules => [] }; }

# ---- http mode: a high-score match fires YARAD + YARAD_HIGH ----
{
    require HTTP::Tiny;
    no warnings 'redefine';
    local *HTTP::Tiny::post = sub {
        return { success => 1, status => 200,
                 content => '{"matches":[{"rule":"Evil_Macro","namespace":"local","meta":{"score":90}}]}' };
    };
    my $pms  = fresh_pms();
    my $conf = { yarad_url => 'http://x:8079', yarad_timeout => 5, yarad_high_score => 75 };
    my $msg  = "From: a\@b\n\nbody";
    my $ok = $self->_scan_http($pms, $conf, \$msg);
    is($ok, 1, 'http scan completed');
    is($pms->{yarad_matched}, 1, 'http: matched');
    is($pms->{yarad_high}, 1, 'http: high-score hit sets yarad_high');
    is_deeply($pms->{yarad_rules}, ['Evil_Macro'], 'http: rule name captured');
    is($self->check_yarad($pms), 1, 'check_yarad fires on a match');
    is($self->check_yarad_high($pms), 1, 'check_yarad_high fires on a high score');
}

# ---- http mode: a low-score match fires YARAD but NOT YARAD_HIGH ----
{
    no warnings 'redefine';
    local *HTTP::Tiny::post = sub {
        return { success => 1, status => 200,
                 content => '{"matches":[{"rule":"Soft_Hit","meta":{"score":10}}]}' };
    };
    my $pms  = fresh_pms();
    my $conf = { yarad_url => 'http://x', yarad_high_score => 75 };
    my $msg  = "m";
    $self->_scan_http($pms, $conf, \$msg);
    is($pms->{yarad_matched}, 1, 'http low: matched');
    is($pms->{yarad_high}, 0, 'http low: yarad_high stays 0 below threshold');
}

# ---- http mode: clean verdict ----
{
    no warnings 'redefine';
    local *HTTP::Tiny::post = sub { return { success => 1, status => 200, content => '{"matches":[]}' }; };
    my $pms  = fresh_pms();
    $self->_scan_http($pms, { yarad_url => 'http://x' }, \(my $m = 'm'));
    is($pms->{yarad_matched}, 0, 'http clean: no match');
    is($self->check_yarad($pms), 0, 'check_yarad off on clean');
}

# ---- http mode: transport error -> undef (caller applies fail-open) ----
{
    no warnings 'redefine';
    local *HTTP::Tiny::post = sub { return { success => 0, status => 599, reason => 'Timeout', content => '' }; };
    my $pms = fresh_pms();
    my $ok  = $self->_scan_http($pms, { yarad_url => 'http://x' }, \(my $m = 'm'));
    is($ok, undef, 'http error returns undef');
}

# ---- shellout mode: fake yarad-scan reporting a match (exit 1) ----
my $dir = tempdir(CLEANUP => 1);
sub fake_scan {
    my ($name, $body) = @_;
    my $p = "$dir/$name";
    open(my $fh, '>', $p) or die $!;
    print $fh $body;
    close($fh);
    chmod 0755, $p;
    return $p;
}
{
    my $bin = fake_scan('match', "#!/bin/sh\ncat >/dev/null\necho 'MATCH Evil_Doc (local)'\nexit 1\n");
    my $pms  = fresh_pms();
    my $conf = { yarad_scan_bin => $bin, yarad_url => 'http://x', yarad_timeout => 5 };
    my $ok = $self->_scan_shellout($pms, $conf, \(my $m = 'message'));
    is($ok, 1, 'shellout match completed');
    is($pms->{yarad_matched}, 1, 'shellout: matched');
    is_deeply($pms->{yarad_rules}, ['Evil_Doc'], 'shellout: rule parsed from MATCH line');
}

# ---- shellout mode: clean (exit 0) ----
{
    my $bin = fake_scan('clean', "#!/bin/sh\ncat >/dev/null\nexit 0\n");
    my $pms = fresh_pms();
    my $ok = $self->_scan_shellout($pms, { yarad_scan_bin => $bin, yarad_url => 'http://x' }, \(my $m = 'm'));
    is($ok, 1, 'shellout clean completed');
    is($pms->{yarad_matched}, 0, 'shellout clean: no match');
}

# ---- shellout mode: client error (exit 2) -> undef ----
{
    my $bin = fake_scan('err', "#!/bin/sh\ncat >/dev/null\nexit 2\n");
    my $pms = fresh_pms();
    my $ok = $self->_scan_shellout($pms, { yarad_scan_bin => $bin, yarad_url => 'http://x' }, \(my $m = 'm'));
    is($ok, undef, 'shellout client error returns undef');
}

# ---- shellout mode: missing binary -> undef ----
{
    my $pms = fresh_pms();
    my $ok = $self->_scan_shellout($pms, { yarad_scan_bin => "$dir/does-not-exist", yarad_url => 'http://x' }, \(my $m = 'm'));
    is($ok, undef, 'shellout missing binary returns undef');
}

# ---- _token: reads + trims a token file; undef when unset ----
{
    my $tf = "$dir/tok";
    open(my $fh, '>', $tf) or die $!; print $fh "  secret\n"; close($fh);
    is($self->_token({ yarad_token_file => $tf }), 'secret', '_token trims file content');
    is($self->_token({ yarad_token_file => '' }), undef, '_token undef when unset');
}

done_testing();
