#!/usr/bin/env perl
# SPDX-License-Identifier: Apache-2.0
#
# The webhook receiver of the integration tests: tests/itest.sh.
#
# Usage:
#   receiver.pl PORT
#
# Accepts plain HTTP requests on PORT, one at a time, and answers each with
# 200 and an empty body. For each request it prints one line:
#
#   received SECONDS KIND TOKEN_ID SIGNATURE
#
# SECONDS is the moment the whole request had arrived, in seconds since the
# epoch with microseconds, read from the same kernel clock as `date` in the
# other containers of the run. KIND and TOKEN_ID are the fields `kind` and
# `token_id` of the event, or `-`; SIGNATURE says whether the request carried
# a signature header of the documented form (`signed` or `unsigned`). The
# signature itself is checked by the tests of the sink, not here. Nothing
# else of the request is printed.
#
# It runs on the internal network of the test only. A request that is too
# large or too slow is dropped, so that no request can hold up the next.

use strict;
use warnings;

use IO::Socket::INET;
use Time::HiRes qw(time);

my $port = $ARGV[0] // die "Usage: receiver.pl PORT\n";
my $max_head = 64 * 1024;
my $max_body = 1024 * 1024;

my $server = IO::Socket::INET->new(
    LocalAddr => '0.0.0.0',
    LocalPort => $port,
    Proto     => 'tcp',
    Listen    => 16,
    ReuseAddr => 1,
) or die "receiver: cannot listen on port $port: $!\n";

$| = 1;
print "receiver: listening\n";

sub receive {
    my ($client) = @_;
    binmode $client;
    my $head = '';
    while (index($head, "\r\n\r\n") < 0) {
        die "too long\n" if length $head > $max_head;
        my $count = sysread($client, $head, 4096, length $head);
        die "closed\n" unless $count;
    }
    my ($headers, $body) = split /\r\n\r\n/, $head, 2;
    my ($length) = $headers =~ /^content-length:[ \t]*(\d{1,9})\r?$/mi;
    die "no length\n" unless defined $length;
    die "too long\n" if $length > $max_body;
    while (length $body < $length) {
        my $count = sysread($client, $body, $length - length $body, length $body);
        die "closed\n" unless $count;
    }
    my $at = time;
    my ($kind) = $body =~ /"kind":"([a-z_]{1,64})"/;
    my ($token) = $body =~ /"token_id":"([A-Za-z0-9._-]{1,128})"/;
    my $signed = $headers =~ /^x-pgsnare-signature:[ \t]*v1=[0-9a-f]{64}\r?$/mi
        ? 'signed' : 'unsigned';
    printf "received %.6f %s %s %s\n", $at, $kind // '-', $token // '-', $signed;
    syswrite($client, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
}

while (1) {
    my $client = $server->accept or next;
    eval {
        local $SIG{ALRM} = sub { die "too slow\n" };
        alarm 5;
        receive($client);
        alarm 0;
        1;
    } or print "receiver: dropped a request: $@";
    alarm 0;
    close $client;
}
