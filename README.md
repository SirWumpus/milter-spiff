[![SnertSoft: We Serve Your Server](Img/logo-300x74.png)](http://software.snert.com/)

![Spaceman Spiff prepares to frag yet another evil spamzulla](Img/spiff.gif)  

milter-spiff  « Sender Permitted If From »
==========================================

Copyright 2004, 2019 by Anthony Howe.  All rights reserved.


WARNING
-------

THIS IS MAIL FILTERING SOFTWARE AND WILL BLOCK MAIL THAT FAILS TO PASS A GIVEN SET OF TESTS.  SNERTSOFT AND THE AUTHOR DO NOT ACCEPT ANY RESPONSIBLITY FOR MAIL REJECTED OR POSSIBLE LOSS OF BUSINESSS THROUGH THE USE OF THIS SOFTWARE.  BY INSTALLING THIS SOFTWARE THE CLIENT UNDERSTANDS AND ACCEPTS THE RISKS INVOLVED.


Description
-----------

This [Sendmail](http://www.sendmail.org/) mail filter is an independent implementation of the Sender Policy Framework
version 1 protocol also known as _SPF Classic_, now [RFC 4408](https://tools.ietf.org/html/rfc4408).  This mail filter will accept, tag, reject, and/or discard email according to a domain's authorized mail source as published using SPF records.


Usage
-----

        milter-spiff [options ...] [arguments ...]

Options can be expressed in four different ways.  Boolean options are expressed as `+option` or `-option` to turn the option on or off respectively.  Options that required a value are expressed as `option=value` or `option+=value` for appending to a value list.  Note that the `+option` and `-option` syntax are equivalent to `option=1` and `option=0` respectively.  Option names are case insensitive.

Some options, like `+help` or `-help`, are treated as immediate actions or commands.  Unknown options are ignored.  The first command-line argument is that which does not adhere to the above option syntax.  The special command-line argument `--` can be used to explicitly signal an end to the list of options.

The default options, as shown below, can be altered by specifying them on the command-line or within an option file, which simply contains command-line options one or more per line and/or on multiple lines.  Comments are allowed and are denoted by a line starting with a hash (#) character.  If the `file=` option is defined and not empty, then it is parsed first followed by the command-line options.

Note that there may be additional options that are listed in the option summary given by `+help` or `-help` that are not described here.


- - -
### access-db=/etc/mail/access.db

The type and location of the read-only access key-value map.  It provides a centralised means to black and white list hosts, domains, mail addresses, etc.  The following methods are supported:

        text!/path/map.txt                      R/O text file, memory hash
        /path/map.db                            Berkeley DB hash format
        db!/path/map.db                         Berkeley DB hash format
        db!btree!/path/map.db                   Berkeley DB btree format
        sql!/path/database                      An SQLite3 database
        socketmap!host:port                     Sendmail style socket-map
        socketmap!/path/local/socket            Sendmail style socket-map
        socketmap!123.45.67.89:port             Sendmail style socket-map
        socketmap![2001:0DB8::1234]:port        Sendmail style socket-map

If `:port` is omitted, the default is `7953`.

The `access-db` contains key-value pairs.  Lookups are performed from most to least specific, stopping on the first entry found.  Keys are case-insensitive.

An IPv4 lookup is repeated several times reducing the IP address by one octet from right to left until a match is found.

        tag:192.0.2.9
        tag:192.0.2
        tag:192.0
        tag:192

An IPv6 lookup is repeated several times reducing the IP address by one 16-bit word from right to left until a match is found.

        tag:2001:0DB8:0:0:0:0:1234:5678
        tag:2001:0DB8:0:0:0:0:1234
        tag:2001:0DB8:0:0:0:0
        tag:2001:0DB8:0:0:0
        tag:2001:0DB8:0:0
        tag:2001:0DB8:0:0
        tag:2001:0DB8:0
        tag:2001:0DB8
        tag:2001

A domain lookup is repeated several times reducing the domain by one label from left to right until a match is found.

        tag:[ipv6:2001:0DB8::1234:5678]
        tag:[192.0.2.9]
        tag:sub.domain.tld
        tag:domain.tld
        tag:tld
        tag:

An email lookup is similar to a domain lookup, the exact address is first tried, then the address's domain, and finally the local part of the address.

        tag:account@sub.domain.tld
        tag:sub.domain.tld
        tag:domain.tld
        tag:tld
        tag:account@
        tag:

If a key is found and is a milter specific tag (ie. `milter-spiff-Connect`, `milter-spiff-To`), then the value is processed as a pattern list and the result returned.  The Sendmail variants cannot have a pattern list.  A pattern list is a whitespace separated list of _pattern-action_ pairs followed by an optional default _action_.  The supported patterns are:

        [network/cidr]action            Classless Inter-Domain Routing
        !pattern!action                 Simple fast text matching.
        /regex/action                   POSIX Extended Regular Expressions

The CIDR will only ever match for IP address related lookups.

A `!pattern!` uses an astrisk (\*) for a wildcard, scanning over zero or more characters; a question-mark (?) matches any single character; a backslash followed by any character treats it as a literal (it loses any special meaning).

        !abc!           exact match for 'abc'
        !abc*!          match 'abc' at start of string
        !*abc!          match 'abc' at the end of string
        !abc*def!       match 'abc' at the start and match 'def' at the end, maybe with stuff in between.
        !*abc*def*!     find 'abc', then find 'def'

For black-white lookups, the following actions are recognised: `OK` or `RELAY` (allow), `REJECT` or `ERROR` (deny), `DISCARD` (accept & discard), `SKIP` or `DUNNO` (stop lookup, no result), and `NEXT` (opposite of `SKIP`, resume lookup).  Its possible to specify an empty action after a pattern, which is treated like `SKIP` returning an undefined result.  Other options may specify other actions.

Below is a list of supported tags.  Other options may specify additional tags.

        milter-spiff-Connect:client-ip          value           § Can be a pattern list.
        milter-spiff-Connect:[client-ip]        value           § Can be a pattern list.
        milter-spiff-Connect:client-domain      value           § Can be a pattern list.
        milter-spiff-Connect:                   value           § Can be a pattern list.
        Connect:client-ip                       value
        Connect:[client-ip]                     value
        Connect:client-domain                   value

All mail sent by a connecting _client-ip_, unresolved _client-ip_ address or IP addresses that resolve to a _client-domain_ are black or white-listed.  These allows you to white-list your network for mail sent internally and off-site, or connections from outside networks.  *Note that Sendmail also has special semantics for `Connect:` and untagged forms.*

        milter-spiff-Auth:auth_authen           value           § Can be a pattern list.
        milter-spiff-Auth:                      value           § Can be a pattern list.

All mail from the authenticated sender, as given by sendmail's `{auth_authen}` macro, is black or white-listed.  The string searched by the pattern list will be the sender-address.  The empty form of `milter-spiff-Auth:` allows for a milter specific default only when `{auth_authen}` is defined.

        milter-spiff-From:sender-address        value           § Can be a pattern list.
        milter-spiff-From:sender-domain         value           § Can be a pattern list.
        milter-spiff-From:sender@               value           § Can be a pattern list.
        milter-spiff-From:                      value           § Can be a pattern list.
        From:sender-address                     value
        From:sender-domain                      value
        From:sender@                            value

All mail from the _sender-address_, _sender-domain_, or that begins with _sender_ is black or white-listed.  In the case of a _+detailed_ email address, the left hand side of the _+detail_ is used for the _sender@_ lookup.  *Note that Sendmail also has special semantics for From: and untagged forms.*

        milter-spiff-To:recipient-address       value           § Can be a pattern list.
        milter-spiff-To:recipient-domain        value           § Can be a pattern list.
        milter-spiff-To:recipient@              value           § Can be a pattern list.
        milter-spiff-To:                        value           § Can be a pattern list.
        Spam:recipient-address                  value           (FRIEND or HATER are recognised)
        Spam:recipient-domain                   value           (FRIEND or HATER are recognised)
        Spam:recipient@                         value           (FRIEND or HATER are recognised)
        To:recipient-address                    value
        To:recipient-domain                     value
        To:recipient@                           value

All mail to the _recipient-address_, _recipient-domain_, or that begins with _recipient_ is black or white-listed.  In the case of a _+detailed_ email address, the left hand side of the _+detail_ is used for the _recipient@_ lookup.  *Note that Sendmail also has special semantics for `Spam:`, `To:`, and untagged forms.*

The `milter-spiff-Connect:` and `milter-spiff-To:` tags provide a milter specific means to override the Sendmail variants.  For example, you normally white list your local network through any and all milters, but on the odd occasion you might want to actually scan mail from inside going out, without removing the `Connect:` tag that allows Sendmail to relay for your network or white listing for other milters.  So for example if you have Sendmail tags like:

        To:mx.example.com                       RELAY

You might have to add milter specific overrides in order to make sure the mail still gets filtered:

        To:mx.example.com                       RELAY
        milter-spiff-To:mx.example.com          SKIP

Some additional examples:

        milter-spiff-Connect:80.94              [80.94.96.0/20]OK REJECT

Accept connections from the netblock 80.94.96.0/20 (80.94.96.0 through to 80.94.111.255) and rejecting anything else in 80.94.0.0/16.

        milter-spiff-Connect:192.0.2            /^192\.0\.2\.8[0-9]/OK REJECT

Accept connections from 192.0.2.80 through to 192.0.2.89, reject everything else in 192.0.2.0/24.

        milter-spiff-To:example.com             /^john@.+/OK /^fred\+.*@.*/OK REJECT

Accept mail to <john@example.com> and <fred@example.com> when fred's address contains a plus-detail in the address.  Reject everything else to example.com.

        milter-spiff-To:example.net             !*+*@*!REJECT !*.smith@*!REJECT /^[0-9\].*/REJECT

Reject mail to example.net using a plus-detail address or to any user who's last name is "smith" or addresses starting with a digit.  No default given, so B/W processing would continue.

Normally when the _access.db_ lookup matches a milter tag, then the _value_ pattern list is processed and there are no further _access.db_ lookups.  The `NEXT` action allows the _access.db_ lookups to resume and is effectively the opposite of `SKIP`.  Consider the following examples:

        milter-spiff-To:com                     /@com/REJECT  NEXT
        To:com                                  OK

Reject mail to places like _compaq.com_ or _com.com_ if the pattern matches, but resume the _access.db_ lookups otherwise.

        milter-spiff-To:aol.com                 /^[a-zA-Z0-9!#$&'*+=?^_`{|}~.-]{3,16}@aol.com$/NEXT REJECT
        To:fred@aol.com                         OK

AOL local parts are between 3 and 16 characters long and can contain dots and RFC 2822 atext characters except `%` and `/`.  The `NEXT` used above allows one simple regex to validate the format of the address and resume lookups of white listed and/or black listed addresses.


- - -
### best-guess-txt=

If the initial SPF test does not yield a Pass for any reason, then we check this "best guess" TXT record (eg. `v=spf1 a/24 mx/24 ptr`) to see if it yields a Pass result.  If the best guess passes, then the message is accepted, else the original SPF result is used.  This option is disabled by default.


- - -
### +daemon

Start as a background daemon or foreground application.


- - -
### file=/etc/mail/milter-spiff.cf

Read the option file before command line options.  This option is set by default.  To disable the use of an option file, simply say `file=''`.


- - -
### -help or +help

Write the option summary to standard output and exit.  The output is suitable for use as an option file.


- - -
### helo-policy=

Check the SMTP `HELO` or `EHLO` argument against any published SPF records.  See also `mail-policy=` option.  The `helo-policy=` option specifies a comma separated list of _result-action_ words from the table below.  The _result-action_ table is in order of priorty from strongest SPF result / safest action to weakest SPF result / most drastic action.  This option is disabled by default.

        fail-tag                 Tag the subject on a Fail result.
        fail-reject              Reject the message on a Fail result.
        fail-discard             Discard the message on a Fail result.
        softfail-tag             Tag the subject on a SoftFail result.
        softfail-reject          Reject the message on a SoftFail result.
        softfail-discard         Discard the message on a SoftFail result.

A reasonable setting might be `helo-policy=softfail-tag,fail-reject`.

- - -
### mail-policy=

Check the SMTP `MAIL FROM:` domain against any published SPF records.  See also `helo-policy=` option.  The `mail-policy=` option specifies a comma separated list of _result-action_ words from the table below.  The _result-action_ table is in order of priorty from strongest SPF result / safest action to weakest SPF result / most drastic action.  This option is disabled by
default.

        fail-tag                 Tag the subject on a Fail result.
        fail-reject              Reject the message on a Fail result.
        fail-discard             Discard the message on a Fail result.
        softfail-tag             Tag the subject on a SoftFail result.
        softfail-reject          Reject the message on a SoftFail result.
        softfail-discard         Discard the message on a SoftFail result.

A reasonable setting might be `mail-policy=softfail-tag,fail-reject`.


- - -
### milter-socket=unix:/var/run/milter/milter-spiff.socket

A socket specifier used to communicate between Sendmail and `milter-spiff`.  Typically a unix named socket or a host:port.  This value must match the value specified for the `INPUT_MAIL_FILTER()` macro in the sendmail.mc file.  The accepted syntax is:

        {unix|local}:/path/to/file              A named pipe. (default)
        inet:port@{hostname|ip-address}         An IPV4 socket.
        inet6:port@{hostname|ip-address}        An IPV6 socket.


- - -
### milter-timeout=7210

The sendmail/milter I/O timeout in seconds.


- - -
### +one-rcpt-per-null

When the sender is `MAIL FROM:<>`, then there can only be one `RCPT TO:` specified since the null address is only used to return a Delivery Status Notification or Message Disposition Notification to the original sender and its not possible to have two or more sender's for one message (in theory).


- - -
### pid-file=/var/run/milter/milter-spiff.pid

The file path of where to save the process-id.

- - -
### policy=none

Policy to apply when a DSN or MDN does not reference a message that originated here or has expired.  Specify none, quarantine, reject, or discard.

- - -
### -quit or +quit

Quit an already running instance of the milter and exit.  This is equivalent to:

        kill -QUIT `cat /var/run/milter/milter-spiff.pid`.

- - -
### +received-spf-headers

Add `Received-SPF:` trace headers with results of `HELO` and `MAIL FROM:` checks.  There may be multiple instances of this header, one for each participating mail server, in which case they represent the most recent to oldest, similar to the way `Received:` headers are added.  This ordering is handled by Sendmail and not configurable.


- - -
### -restart or +restart

Terminate an already running instance of the milter before starting.


- - -
### run-group=milter

The process runtime group name to be used when started by root.

- - -
### run-user=milter

The process runtime user name to be used when started by root.


- - -
### +smtp-auth-ok

Allow SMTP authenticated senders to send unscanned mail.  See also the `milter-spiff-auth:` tag (`access-db=`) for finer granularity of control.


- - -
### subject-tag=[SPAM]

Subject tag prefix for messages that fail the SPF check.  To disable the subject tag specify: `subject-tag=''` or see `helo-policy=` or `mail-policy=` or both options.


- - -
### verbose=info

A comma separated list of how much detail to write to the mail log.  Those mark with `§` have meaning for this milter.

        §  all          All messages
        §  0            Log nothing.
        §  info         General info messages. (default)
        §  trace        Trace progress through the milter.
        §  parse        Details from parsing addresses or special strings.
        §  debug        Lots of debug messages.
           dialog       I/O from Communications dialog
           state        State transitions of message body scanner.
        §  dns          Trace & debug of DNS operations
           cache        Cache get/put/gc operations.
        §  database     Sendmail database lookups.
           socket-fd    socket open & close calls
           socket-all   All socket operations & I/O
        §  libmilter    libmilter engine diagnostics


- - -
### work-dir=/var/tmp

The working directory of the process.  Normally serves no purpose unless the kernel option that permits daemon process core dumps is set.


SMTP Responses
--------------

This is the list of possible SMTP responses.

* 553 5.1.0 imbalanced angle brackets in path  
  The path given for a `MAIL` or `RCPT` command is missing a closing angle bracket

* 553 5.1.0 address does not conform to RFC 2821 syntax  
  The address is missing the angle brackets, `<` and `>`, as required by the RFC grammar.

* 553 5.1.0 local-part too long  
  The stuff before the `@` is too long.

* 553 5.1.[37] invalid local part  
  The stuff before the `@` sign contains unacceptable characters.

* 553 5.1.0 domain name too long  
  The stuff after the `@` is too long.

* 553 5.1.7 address incomplete  
  Expecting a domain.tld after the `@` sign and found none.

* 553 5.1.[37] invalid domain name  
  The domain after the `@` sign contains unacceptable characters.

* 451 4.4.3 HELO .+ from .+ SPF result .+: .*  
  There was a DNS lookup error for the `HELO` argument.  See `helo-policy=` option

* 550 5.7.1 HELO .+ from .+ SPF result .+; .*  
  The HELO argument failed the SPF check.  See `helo-policy=` option

* 451 4.4.3 sender <.+> via .+ SPF result .+: .*  
  There was a DNS lookup error for the MAIL FROM: domain.  See `mail-policy=` option

* 550 5.7.1 sender <.+> via .+ SPF result .+; .*  
  The MAIL FROM: domain failed the SPF check.  See `mail-policy=` option


Build & Install
---------------

* Install `SQLite` from a package if desired.  Prior to [LibSnert's](https://github.com/SirWumpus/libsnert) availability on GitHub, the old `libsnert` tarballs included SQLite, but the GitHub [libsnert](https://github.com/SirWumpus/libsnert) repository does not, so it needs to be installed separately.   `milter-spiff` does not require it, but other milters that need a cache will.

* If you have never built a milter for Sendmail, then please make sure that you build and install `libmilter` (or install a pre-built package), which is _not_ built by default when you build Sendmail.  Please read the `libmilter` documentation.  Briefly, it should be something like this:

        cd (path to)/sendmail-8.13.6/libmilter
        sh Build -c install

* [Build LibSnert](https://github.com/SirWumpus/libsnert#configuration--build) first, do *not* disable `sqlite3` support; it should find the pre-installed version of SQLite if any.

* Building `milter-spiff` should be:

        cd com/snert/src
        git clone https://github.com/SirWumpus/milter-spiff.git
        cd milter-spiff
        autoconf -f             # If ./configure is missing or out of date.
        ./configure --help
        ./configure
        make
        sudo make install

* An example `/usr/local/share/examples/milter-spiff/milter-spiff.mc` is supplied.  This file should be reviewed and the necessary elements inserted into your Sendmail `.mc` file and `sendmail.cf` rebuilt.  Please note the comments on the general milter flags.

* Once installed and configured, start `milter-spiff` and then restart Sendmail.  An example startup script is provided in `/usr/local/share/examples/milter-spiff/milter-spiff.sh`.


Notes
-----

* The minimum desired file ownership and permissions are as follows for a typical Linux system.  For FreeBSD, NetBSD, and OpenBSD the binary and cache locations may differ, but have the same permissions.  Process user `milter` is primary member of group `milter` and secondary member of group `smmsp`.  Note that the milter should be started as `root`, so that it can create a _.pid file_ and _.socket file_ in `/var/run`; after which it will switch process ownership to `milter:milter` before starting the accept socket thread.

        /etc/mail/                              root:smmsp      0750 drwxr-x---
        /etc/mail/access.db                     root:smmsp      0640 -rw-r-----
        /etc/mail/sendmail.cf                   root:smmsp      0640 -rw-r-----
        /etc/mail/milter-spiff.cf               root:root       0644 -rw-r--r--
        /var/run/milter/milter-spiff.pid        milter:milter   0644 -rw-r--r--
        /var/run/milter/milter-spiff.socket     milter:milter   0644 srw-r--r--
        /var/db/milter-spiff                    milter:milter   0644 -rw-r--r-- (*BSD)
        /var/cache/milter-spiff                 milter:milter   0644 -rw-r--r-- (linux)
        /usr/local/libexec/milter-spiff         root:milter     0550 -r-xr-x---


![Spaceman Spiff prepares to frag yet another evil spamzulla](Img/spiff2.gif)  
