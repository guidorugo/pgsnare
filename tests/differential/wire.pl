#!/usr/bin/env perl
# SPDX-License-Identifier: Apache-2.0
#
# A client that speaks the PostgreSQL protocol message by message, for the
# scenarios no libpq client can run: libpq has no way to ask for a few rows
# of a portal at a time, to give up on a COPY, or to ask for a protocol
# version that does not exist.
#
# Usage:
#   wire.pl CONNINFO COMMAND
#
#   CONNINFO   a libpq keyword/value string. The keywords host, port, user,
#              dbname, sslmode and max_protocol_version are understood.
#              The password comes from the environment (PGPASSWORD).
#   COMMAND    one of:
#     portal      fetch a result three rows at a time
#     copy-fail   start a COPY, send a row and give up
#     function    call a function with a FunctionCall message
#     negotiate   ask for protocol 3.99 with an option no server knows
#
# The script prints every message the server sends from the end of the
# login on, as its type and its body in hexadecimal. That is the output a
# scenario compares between PostgreSQL itself and pgsnare. Two things are
# left out, because they differ from one connection to the next: the body
# of BackendKeyData, and the list of mechanisms in an authentication
# request, which depends on whether the connection uses TLS.
#
# With sslmode=require the connection is handed to `openssl s_client`,
# which asks for TLS the way a PostgreSQL client does.

use strict;
use warnings;

use Digest::SHA qw(sha256 hmac_sha256);
use IO::Socket::INET;
use IPC::Open2;
use MIME::Base64 qw(decode_base64 encode_base64);

my ($conninfo, $command) = @ARGV;
die "Usage: wire.pl CONNINFO COMMAND\n" unless defined $command;

my %option = (host => 'localhost', port => 5432, user => 'postgres', sslmode => 'disable');
for my $pair (split ' ', $conninfo) {
    my ($key, $value) = split /=/, $pair, 2;
    $option{$key} = $value;
}
$option{dbname} //= $option{user};
my $minor = ($option{max_protocol_version} // '3.0') eq '3.2' ? 2 : 0;

# --- The connection ----------------------------------------------------------

my ($reader, $writer, $transport);

sub connect_to_server {
    if ($option{sslmode} eq 'disable') {
        my $socket = IO::Socket::INET->new(
            PeerHost => $option{host},
            PeerPort => $option{port},
            Proto    => 'tcp',
        ) or die "cannot connect: $!\n";
        ($reader, $writer) = ($socket, $socket);
    } else {
        $transport = open2(
            $reader, $writer,
            'sh', '-c',
            'exec openssl s_client -quiet -starttls postgres -connect "$1" 2>/dev/null',
            'sh', "$option{host}:$option{port}",
        );
    }
    binmode $reader;
    binmode $writer;
}

sub send_bytes {
    my ($bytes) = @_;
    my $sent = 0;
    while ($sent < length $bytes) {
        my $count = syswrite($writer, $bytes, length($bytes) - $sent, $sent);
        die "cannot write: $!\n" unless defined $count;
        $sent += $count;
    }
}

sub read_bytes {
    my ($wanted) = @_;
    my $bytes = '';
    while (length($bytes) < $wanted) {
        my $count = sysread($reader, $bytes, $wanted - length($bytes), length($bytes));
        die "cannot read: $!\n" unless defined $count;
        die "the server closed the connection\n" if $count == 0;
    }
    return $bytes;
}

# A message with a type byte: the type and the body.
sub read_message {
    my $header = read_bytes(5);
    my ($type, $length) = unpack 'a N', $header;
    return ($type, read_bytes($length - 4));
}

sub message {
    my ($type, $body) = @_;
    return $type . pack('N', length($body) + 4) . $body;
}

sub startup {
    my ($version_minor, @parameters) = @_;
    my $body = pack('n n', 3, $version_minor);
    $body .= "$_\0" for @parameters;
    $body .= "\0";
    return pack('N', length($body) + 4) . $body;
}

# --- The trace ---------------------------------------------------------------

sub show {
    my ($type, $body) = @_;
    if ($type eq 'K') {
        printf "K (%d bytes)\n", length $body;
    } elsif ($type eq 'R') {
        printf "R %d\n", unpack('N', $body);
    } else {
        printf "%s %s\n", $type, unpack('H*', $body);
    }
}

# Reads and shows messages up to and including one of the given type.
sub show_until {
    my ($last) = @_;
    while (1) {
        my ($type, $body) = read_message();
        show($type, $body);
        return if $type eq $last;
        die "the server reported an error\n" if $type eq 'E' && $last ne 'Z';
    }
}

# --- The login ---------------------------------------------------------------

sub xor_strings {
    my ($left, $right) = @_;
    return $left ^ $right;
}

# PBKDF2 with HMAC-SHA-256 and one block of output, as SCRAM uses it.
sub salted_password {
    my ($password, $salt, $iterations) = @_;
    my $block = hmac_sha256($salt . pack('N', 1), $password);
    my $result = $block;
    for (2 .. $iterations) {
        $block = hmac_sha256($block, $password);
        $result = xor_strings($result, $block);
    }
    return $result;
}

sub scram {
    my $password = $ENV{PGPASSWORD} // die "PGPASSWORD is not set\n";
    my $nonce = encode_base64(pack('N4', map { int rand 2**32 } 1 .. 4), '');
    my $first_bare = "n=,r=$nonce";
    my $first = "n,,$first_bare";
    send_bytes(message('p', "SCRAM-SHA-256\0" . pack('N', length $first) . $first));

    my ($type, $body) = read_message();
    die "expected a SASL challenge\n" unless $type eq 'R' && unpack('N', $body) == 11;
    my $server_first = substr $body, 4;
    my %field = map { split /=/, $_, 2 } split /,/, $server_first;

    my $final_bare = "c=biws,r=$field{r}";
    my $salted = salted_password($password, decode_base64($field{s}), $field{i});
    my $client_key = hmac_sha256('Client Key', $salted);
    my $auth_message = "$first_bare,$server_first,$final_bare";
    my $signature = hmac_sha256($auth_message, sha256($client_key));
    my $proof = encode_base64(xor_strings($client_key, $signature), '');
    send_bytes(message('p', "$final_bare,p=$proof"));

    ($type, $body) = read_message();
    die "the login failed\n" unless $type eq 'R' && unpack('N', $body) == 12;
    ($type, $body) = read_message();
    die "the login failed\n" unless $type eq 'R' && unpack('N', $body) == 0;
}

# Logs in and shows what the server says from then on, up to
# ReadyForQuery.
sub log_in {
    connect_to_server();
    send_bytes(startup($minor, 'user', $option{user}, 'database', $option{dbname}));
    while (1) {
        my ($type, $body) = read_message();
        # A server older than the protocol version asked for says so first.
        next if $type eq 'v';
        die "the server refused the connection\n" unless $type eq 'R';
        die "expected a SASL request\n" unless unpack('N', $body) == 10;
        last;
    }
    scram();
    show_until('Z');
}

# Ends the connection. The TLS helper stays until its server hangs up,
# which a server that waits for a login does not do for a long time, so
# the helper is told to go.
sub disconnect {
    close $writer;
    return unless defined $transport;
    close $reader;
    kill 'TERM', $transport;
    waitpid $transport, 0;
}

sub finish {
    send_bytes(message('X', ''));
    disconnect();
}

sub query {
    my ($sql) = @_;
    send_bytes(message('Q', "$sql\0"));
}

# --- The commands ------------------------------------------------------------

# Execute with a row limit: the server sends that many rows and
# PortalSuspended, and goes on from there with the next Execute.
sub portal {
    log_in();
    my $three_rows = message('E', "cursor\0" . pack('N', 3));
    send_bytes(
        message('P', "numbers\0SELECT n, repeat('x', n) FROM generate_series(1, 10) AS n\0" . pack('n', 0))
        . message('B', "cursor\0numbers\0" . pack('n n n', 0, 0, 0))
        . message('D', "Pcursor\0")
        . $three_rows . $three_rows
        # Flush, so that what was sent so far is answered before the rest.
        . message('H', '')
    );
    # ParseComplete, BindComplete, RowDescription, two times three rows.
    show_until('s');
    show_until('s');
    send_bytes(
        $three_rows . $three_rows
        # An Execute on a portal that has no rows left, a Close, and an
        # Execute on the portal that is gone.
        . $three_rows
        . message('C', "Pcursor\0")
        . $three_rows
        . message('S', '')
    );
    show_until('Z');
    # After the error the session works as before.
    query("SELECT 'after the portal' AS state");
    show_until('Z');
    finish();
}

# A COPY the client starts and then gives up on.
sub copy_fail {
    log_in();
    query('CREATE TABLE given_up (id int, note text)');
    show_until('Z');
    query('COPY given_up FROM STDIN');
    show_until('G');
    send_bytes(message('d', "1\tkept until the end\n") . message('f', "the client changed its mind\0"));
    show_until('Z');
    query('SELECT count(*) FROM given_up');
    show_until('Z');
    finish();
}

# FunctionCall: int4pl(40, 2), with arguments and result in binary.
sub function {
    log_in();
    my $int4pl = 177;
    my $call = pack('N n n n', $int4pl, 1, 1, 2)
        . pack('N N', 4, 40) . pack('N N', 4, 2)
        . pack('n', 1);
    send_bytes(message('F', $call));
    show_until('Z');
    # A function that does not exist.
    send_bytes(message('F', pack('N n n n', 1, 0, 0, 0)));
    show_until('Z');
    finish();
}

# A startup message from the future: protocol 3.99, and a protocol option.
# The server answers with the version it speaks and the option it does not
# know, and goes on to ask for the login.
sub negotiate {
    connect_to_server();
    send_bytes(startup(99, 'user', $option{user}, 'database', $option{dbname},
        '_pq_.pgsnare_scenario', 'on', '_pq_.another', '1'));
    show_until('R');
    disconnect();
}

my %commands = (
    'portal'    => \&portal,
    'copy-fail' => \&copy_fail,
    'function'  => \&function,
    'negotiate' => \&negotiate,
);
my $run = $commands{$command} or die "wire.pl: unknown command: $command\n";
$| = 1;
$run->();
