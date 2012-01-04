/*
 * milter-spiff.c
 *
 * Copyright 2005, 2012 by Anthony Howe. All rights reserved.
 *
 * The following should be added to the sendmail.mc file:
 *
 *	INPUT_MAIL_FILTER(
 *		`milter-spiff',
 *		`S=unix:/var/run/milter-spiff.socket, T=S:10s;R:4m'
 *	)dnl
 *
 * $OpenBSD$
 */

/***********************************************************************
 *** Leave this header alone. Its generate from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 *** You can change the stuff below if the configure script doesn't work.
 ***********************************************************************/

#ifndef RUN_AS_USER
#define RUN_AS_USER			"milter"
#endif

#ifndef RUN_AS_GROUP
#define RUN_AS_GROUP			"milter"
#endif

#ifndef MILTER_CF
#define MILTER_CF			"/etc/mail/" MILTER_NAME ".cf"
#endif

#ifndef PID_FILE
#define PID_FILE			"/var/run/milter/" MILTER_NAME ".pid"
#endif

#ifndef SOCKET_FILE
#define SOCKET_FILE			"/var/run/milter/" MILTER_NAME ".socket"
#endif

#ifndef WORK_DIR
#define WORK_DIR			"/var/tmp"
#endif

#ifndef SENDMAIL_CF
#define SENDMAIL_CF			"/etc/mail/sendmail.cf"
#endif

/***********************************************************************
 *** No configuration below this point.
 ***********************************************************************/

/* Re-assert this macro just in case. May cause a compiler warning. */
#define _REENTRANT	1

#include <com/snert/lib/version.h>

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>
#include <netdb.h>

#include <com/snert/lib/sys/Time.h>
#include <com/snert/lib/mail/limits.h>
#include <com/snert/lib/mail/smf.h>
#include <com/snert/lib/mail/spf.h>
#include <com/snert/lib/mail/smdb.h>
#include <com/snert/lib/net/pdq.h>
#include <com/snert/lib/util/Text.h>
#include <com/snert/lib/util/getopt.h>
#include <com/snert/lib/util/setBitWord.h>

#if LIBSNERT_MAJOR < 1 || LIBSNERT_MINOR < 75
# error "LibSnert 1.75.8 or better is required"
#endif

#ifdef MILTER_BUILD_STRING
# define MILTER_STRING	MILTER_NAME "/" MILTER_VERSION "." MILTER_BUILD_STRING
#else
# define MILTER_STRING	MILTER_NAME "/" MILTER_VERSION
#endif

/***********************************************************************
 *** Constants
 ***********************************************************************/

#define	TAG_FORMAT		"%05d %s: "
#define	TAG_ARGS		data->work.cid, data->work.qid

#define RECEIVED_SPF		"Received-SPF"
#define X_SCANNED_BY		"X-Scanned-By"
#define X_MILTER_PASS		"X-" MILTER_NAME "-Pass"
#define X_MILTER_REPORT		"X-" MILTER_NAME "-Report"

#define SPIFF_FAIL_MASK		0x00F
#define SPIFF_FAIL_LOG		0x001
#define SPIFF_FAIL_TAG		0x002
#define SPIFF_FAIL_REJECT	0x004
#define SPIFF_FAIL_DISCARD	0x008

#define SPIFF_SOFTFAIL_MASK	0x0F0
#define SPIFF_SOFTFAIL_LOG	0x010
#define SPIFF_SOFTFAIL_TAG	0x020
#define SPIFF_SOFTFAIL_REJECT	0x040
#define SPIFF_SOFTFAIL_DISCARD	0x080

#define SPIFF_TEMPERROR_MASK	0xF00
#define SPIFF_TEMPERROR_LOG	0x100
#define SPIFF_TEMPERROR_TAG	0x200
#define SPIFF_TEMPERROR_REJECT	0x400
#define SPIFF_TEMPERROR_DISCARD	0x800

#define X_SMFIS_TAG		(-2)

#define FLAG_REJECT_AT_MAIL	1

/***********************************************************************
 *** Global Variables
 ***********************************************************************/

typedef struct {
	smfWork work;
	int hasSubject;				/* per message */
	int spfHelo;				/* per connection */
	int spfMail;				/* per message */
	const char *spfHeloError;		/* per connection */
	const char *spfMailError;		/* per message */
	char helo[SMTP_DOMAIN_LENGTH+1];	/* per connection */
	char line[SMTP_TEXT_LINE_LENGTH+1];	/* general purpose */
	char subject[SMTP_TEXT_LINE_LENGTH+1];	/* per message */
	char client_addr[IPV6_TAG_LENGTH+IPV6_STRING_LENGTH];	/* per connection */
} *workspace;

struct bitword result_action_words[] = {
	{ SPIFF_FAIL_TAG, 		"fail-tag" },
	{ SPIFF_FAIL_REJECT, 		"fail-reject" },
	{ SPIFF_FAIL_DISCARD, 		"fail-discard" },
	{ SPIFF_SOFTFAIL_TAG,		"softfail-tag" },
	{ SPIFF_SOFTFAIL_REJECT,	"softfail-reject" },
	{ SPIFF_SOFTFAIL_DISCARD,	"softfail-discard" },
	{ 0, 				NULL }
};

static long spfHelo;
static long spfMail;

#define USAGE_HELO_POLICY						\
  "Check HELO argument and act according to a comma separated list:\n"	\
"#\tsoftfail-tag, softfail-reject, softfail-discard\n"			\
"#\tfail-tag, fail-reject, fail-discard,\n"				\
"#\n"									\
"# Example: helo-policy=softfail-tag,fail-reject\n"			\
"#"

#define USAGE_MAIL_POLICY							\
  "Check MAIL FROM: domain and act according to a comma separated list:\n"	\
"#\tsoftfail-tag, softfail-reject, softfail-discard\n"				\
"#\tfail-tag, fail-reject, fail-discard,\n"					\
"#\n"										\
"# Example: mail-policy=softfail-tag,fail-reject\n"				\
"#"

#define USAGE_REJECT_AT_MAIL						\
  "If the message fails the SPF check, we can reject immediately\n"	\
"# in response to the MAIL FROM: command or wait until after each\n"	\
"# RCPT TO: has had a chance to pass through white-list lookups.\n"	\
"#"

static Option optIntro			= { "",				NULL,		"\n# " MILTER_NAME "/" MILTER_VERSION "\n#\n# " MILTER_COPYRIGHT "\n#\n" };
static Option optBestGuessTxt		= { "best-guest-txt",		"",		"Try this best-guess TXT record if the initial SPF check does not Pass." };
static Option optHeloPolicy		= { "helo-policy",		"",		USAGE_HELO_POLICY };
static Option optMailPolicy		= { "mail-policy",		"",		USAGE_MAIL_POLICY };
static Option optReceivedSpfHeaders	= { "received-spf-headers",	"+",		"Add Received-SPF: headers with results of HELO and MAIL FROM: checks." };
static Option optRejectAtMail		= { "reject-at-mail"		"-",		USAGE_REJECT_AT_MAIL };
static Option optSubjectTag		= { "subject-tag",		"[SPAM]",	"Subject tag for messages that fail the SPF check." };

#ifdef DROPPED_ADD_HEADERS
static Option optAddHeaders		= { "add-headers",		"-",		"Add extra informational headers when message passes." };
#endif

static Option *optTable[] = {
	&optIntro,
#ifdef DROPPED_ADD_HEADERS
	&optAddHeaders,
#endif
	&optBestGuessTxt,
	PDQ_OPTIONS_TABLE,
	&optHeloPolicy,
	&optMailPolicy,
	&optReceivedSpfHeaders,
	&optRejectAtMail,
	&optSubjectTag,
	&spfTempErrorDns,
	NULL
};

/***********************************************************************
 *** Handlers
 ***********************************************************************/

/*
 * Open and allocate per-connection resources.
 */
static sfsistat
filterOpen(SMFICTX *ctx, char *client_name, _SOCK_ADDR *raw_client_addr)
{
	int access;
	workspace data;

	if (raw_client_addr == NULL) {
		smfLog(SMF_LOG_TRACE, "filterOpen() got NULL socket address, accepting connection");
		goto error0;
	}

	if (raw_client_addr->sa_family != AF_INET
#ifdef HAVE_STRUCT_SOCKADDR_IN6
	&& raw_client_addr->sa_family != AF_INET6
#endif
	) {
		smfLog(SMF_LOG_TRACE, "filterOpen() unsupported socket address type, accepting connection");
		goto error0;
	}

	if ((data = calloc(1, sizeof *data)) == NULL)
		goto error0;

	data->work.ctx = ctx;
	data->work.qid = smfNoQueue;
	data->work.cid = smfOpenProlog(ctx, client_name, raw_client_addr, data->client_addr, sizeof (data->client_addr));

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterOpen(%lx, '%s', [%s])", TAG_ARGS, (long) ctx, client_name, data->client_addr);

	data->spfHelo = SPF_NONE;

	if (smfi_setpriv(ctx, (void *) data) == MI_FAILURE) {
		syslog(LOG_ERR, TAG_FORMAT "failed to save workspace", TAG_ARGS);
		goto error1;
	}

	access = smfAccessHost(&data->work, MILTER_NAME "-connect:", client_name, data->client_addr, SMDB_ACCESS_OK);

	switch (access) {
#ifdef ENABLE_BLACKLIST
	case SMDB_ACCESS_REJECT:
		/* Report this mail error ourselves, because sendmail/milter API
		 * fails to report xxfi_connect handler rejections.
		 */
		smfLog(SMF_LOG_ERROR, TAG_FORMAT "connection %s [%s] blocked", TAG_ARGS, client_name, data->client_addr);
		return smfReply(&data->work, 550, "5.7.1", "connection %s [%s] blocked", client_name, data->client_addr);
#endif
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
	}

	return SMFIS_CONTINUE;
error1:
	free(data);
error0:
	return SMFIS_ACCEPT;
}

static sfsistat
filterHelo(SMFICTX * ctx, char *helohost)
{
	int result;
	workspace data;
	const char *error;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterHelo");

	/* Reset this again. A HELO/EHLO is treated like a RSET command,
	 * which means we arrive here after the connection but also after
	 * MAIL or RCPT, in which case $i (data->work.qid) is invalid.
	 * This could be handled in filterAbort(), but most of my milters
	 * don't use filterAbort().
	 */
	data->work.qid = smfNoQueue;

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterHelo(%lx, '%s')", TAG_ARGS, (long) ctx, helohost);

	if (data->work.skipConnection)
		return SMFIS_CONTINUE;

	data->helo[0] = '\0';
	data->spfHelo = SPF_NONE;
	data->spfHeloError = smfUndefined;

	if (helohost != NULL) {
		TextCopy(data->helo, sizeof(data->helo), helohost);
		error = spfCheckDomain(data->client_addr, helohost, &data->spfHelo);
		if (error != NULL)
			data->spfHeloError = error;

		if (*optBestGuessTxt.string != '\0' && data->spfHelo != SPF_PASS) {
			(void) spfCheckHeloMailTxt(data->client_addr, NULL, helohost, optBestGuessTxt.string, &result);
			if (result == SPF_PASS)
				data->spfHelo = SPF_PASS;
		}

		smfLog(
			SMF_LOG_DEBUG, TAG_FORMAT "HELO %s from %s SPF result %s; %s", TAG_ARGS,
			data->helo, data->client_addr, spfResultString[data->spfHelo],
			data->spfHeloError
		);
	}

	return SMFIS_CONTINUE;
}

static sfsistat
spfFailAction(long option)
{
	sfsistat rc = SMFIS_CONTINUE;

	if (option & SPIFF_FAIL_TAG)
		rc = X_SMFIS_TAG;

	else if (option & SPIFF_FAIL_REJECT)
		rc = SMFIS_REJECT;

	else if (option & SPIFF_FAIL_DISCARD)
		rc = SMFIS_DISCARD;

	smfLog(SMF_LOG_DEBUG, "spfFailAction(%lx) rc=%d", option, rc);

	return rc;
}

static sfsistat
spfSoftFailAction(long option)
{
	sfsistat rc = SMFIS_CONTINUE;

	if (option & SPIFF_SOFTFAIL_TAG)
		rc = X_SMFIS_TAG;

	else if (option & SPIFF_SOFTFAIL_REJECT)
		rc = SMFIS_REJECT;

	else if (option & SPIFF_SOFTFAIL_DISCARD)
		rc = SMFIS_DISCARD;

	smfLog(SMF_LOG_DEBUG, "spfSoftFailAction(%lx) rc=%d", option, rc);

	return rc;
}

static sfsistat
spfTempErrorAction(long option)
{
	sfsistat rc = SMFIS_CONTINUE;

	/* If we are only tagging SPF SoftFail or Fail results,
	 * then ignore TempError results and accept the message.
	 * The previous behaviour was to reject the message with
	 * a 451 response as recommended in SPF Internet Draft 2
	 * section 2.5.6.TempError.
	 */
	if (option & SPIFF_FAIL_REJECT)
		rc = SMFIS_TEMPFAIL;

	else if (option & SPIFF_SOFTFAIL_REJECT)
		rc = SMFIS_TEMPFAIL;

	smfLog(SMF_LOG_DEBUG, "spfTempErrorAction(%lx) rc=%d", option, rc);

	return rc;
}


static sfsistat
spfAction(long option, int spf)
{
	sfsistat rc = SMFIS_CONTINUE;

	switch (spf) {
	case SPF_PASS:
		rc = SMFIS_ACCEPT;
		break;

	case SPF_FAIL:
		rc = spfFailAction(option);
		break;

	case SPF_SOFTFAIL:
		rc = spfSoftFailAction(option);
		break;

	case SPF_TEMP_ERROR:
		rc = spfTempErrorAction(option);
		break;
	}

	smfLog(SMF_LOG_DEBUG, "spfAction(%lx, %d=%s) rc=%d", option, spf, spfResultString[spf], rc);

	return rc;
}

static sfsistat
spfCheckResult(workspace data)
{
	smfLog(SMF_LOG_TRACE, TAG_FORMAT "spfCheckResult(%lx) spfHelo=%s spfMail=%s", TAG_ARGS, (long) data, spfResultString[data->spfHelo], spfResultString[data->spfMail]);

	switch (spfAction(spfHelo, data->spfHelo)) {
	case SMFIS_TEMPFAIL:
		/* An invalid HELO, which is a not FQDN, will probably generate
		 * a "DNS name not found" error and so return SPF_TEMP_ERROR.
		 * This can happen while many mail clients continue to submit
		 * email via port 25, instead of the MSA port 587. Consider
		 * a Windows machine where the mail client uses the machine's
		 * workgroup name with no Internet domain suffix.
		 *
		 * So when the HELO argument generates an SPF_TEMP_ERROR and
		 * the DNS error corresponds to not found or undefined result,
		 * then treat the test result as SPF_NONE.
		 */
		if (data->spfHeloError == pdqRcodeName(PDQ_RCODE_UNDEFINED) || data->spfHeloError == pdqRcodeName(PDQ_RCODE_ERRNO))
			break;

		return smfReply(
			&data->work, 451, "4.4.3", "HELO %s from %s SPF result %s: %s",
			data->helo, data->client_addr, spfResultString[data->spfHelo],
			data->spfHeloError
		);
	case SMFIS_REJECT:
		return smfReply(
			&data->work, 550, NULL, "HELO %s from %s SPF result %s; %s",
			data->helo, data->client_addr, spfResultString[data->spfHelo],
			data->spfHeloError
		);
	case SMFIS_ACCEPT:
		/* HELO can be used to override MAIL FROM, in particualar for
		 * the DSN address, as outlined in Meng Weng Wong's Dec 2004
		 * white paper.
		 */
		if (*data->work.mail->address.string == '\0')
			return SMFIS_CONTINUE;
		/*@fallthrough@*/
	}

	switch (spfAction(spfMail, data->spfMail)) {
	case SMFIS_TEMPFAIL:
		return smfReply(
			&data->work, 451, "4.4.3", "sender <%s> via %s SPF result %s: %s",
			data->work.mail->address.string, data->client_addr,
			spfResultString[data->spfMail], data->spfMailError
		);
	case SMFIS_REJECT:
		return smfReply(
			&data->work, 550, NULL, "sender <%s> via %s SPF result %s; %s",
			data->work.mail->address.string, data->client_addr,
			spfResultString[data->spfMail], data->spfMailError
		);
	}

	/* Wait until filterEndMessage() to discard as this allows
	 * for white listing by RCPT and for other filters to take
	 * action. We're going to read the entire message anyways
	 * for a discard, so we can wait until filterEndMessage().
	 */

	return SMFIS_CONTINUE;
}

static sfsistat
filterMail(SMFICTX *ctx, char **args)
{
	int result;
	workspace data;
	const char *error;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterMail");

	if ((data->work.qid = smfi_getsymval(ctx, "i")) == NULL)
		data->work.qid = smfNoQueue;

	data->hasSubject = 0;
	data->spfMail = SPF_NONE;
	data->spfMailError = smfUndefined;
	data->work.skipMessage = data->work.skipConnection;

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterMail(%lx, %lx) MAIL='%s'", TAG_ARGS, (long) ctx, (long) args, args[0]);

	switch (smfAccessMail(&data->work, MILTER_NAME "-from:", args[0], SMDB_ACCESS_UNKNOWN)) {
#ifdef ENABLE_BLACKLIST
	case SMDB_ACCESS_REJECT:
		return smfReply(&data->work, 550, "5.7.1", "sender blocked");
#endif
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
	}

	if (smfi_getsymval(ctx, smMacro_auth_authen) != NULL) {
		data->spfHeloError = data->spfMailError = "sender authenticated";
		data->spfHelo = data->spfMail = SPF_PASS;
	}

	else if (data->work.skipConnection) {
		data->spfHeloError = data->spfMailError = "client IP white listed";
		data->spfHelo = data->spfMail = SPF_PASS;
	}

	else if (data->work.skipMessage) {
		data->spfMailError = "sender white listed";
		data->spfMail = SPF_PASS;
	}

	else {
		/* Defer any rejction until RCPT or DATA command so
		 * that we can first check for any white listed RCPT.
		 */
		error = spfCheckHeloMail(data->client_addr, data->helo, args[0], &data->spfMail);
		if (error != NULL)
			data->spfMailError = error;

		if (*optBestGuessTxt.string != '\0' && data->spfMail != SPF_PASS) {
			error = spfCheckHeloMailTxt(data->client_addr, data->helo, args[0], optBestGuessTxt.string, &result);
			if (result == SPF_PASS)
				data->spfMail = SPF_PASS;
		}
	}

	smfLog(
		SMF_LOG_DEBUG, TAG_FORMAT "sender <%s> via %s SPF result %s; %s", TAG_ARGS,
		data->work.mail->address.string, data->client_addr,
		spfResultString[data->spfMail], data->spfMailError
	);

	/* Do we wait for RCPT white listing? */
	if (optRejectAtMail.value)
		return spfCheckResult(data);

	return SMFIS_CONTINUE;
}

static sfsistat
filterRcpt(SMFICTX *ctx, char **args)
{
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterRcpt");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterRcpt(%lx, %lx) RCPT='%s'", TAG_ARGS, (long) ctx, (long) args, args[0]);

	switch (smfAccessRcpt(&data->work, MILTER_NAME "-to:", args[0])) {
	case SMDB_ACCESS_OK:
		/* Explicitly white listed. */
		data->work.skipMessage = 1;
		return SMFIS_CONTINUE;
#ifdef ENABLE_BLACKLIST
	case SMDB_ACCESS_REJECT:
		/* Explicitly black listed. */
		return smfReply(&data->work, 550, "5.7.1", "recipient blocked");
#endif
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
	}

	/* Reject RCPT now if SPF result for HELO or MAIL would reject. */
	return spfCheckResult(data);
}

static sfsistat
filterHeader(SMFICTX *ctx, char *name, char *value)
{
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterHeader");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterHeader(%lx, '%s', '%s')", TAG_ARGS, (long) ctx, name, value);

	if (TextInsensitiveCompare(name, "Subject") == 0) {
		TextCopy(data->subject, sizeof (data->subject), value);
		data->hasSubject = 1;
	}

	return SMFIS_CONTINUE;
}

static sfsistat
filterEndMessage(SMFICTX *ctx)
{
	int tag;
	long length;
	workspace data;
	const char *if_name, *if_addr;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterEndMessage");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterEndMessage(%lx)", TAG_ARGS, (long) ctx);

	if ((if_name = smfi_getsymval(ctx, smMacro_if_name)) == NULL)
		if_name = smfUndefined;
	if ((if_addr = smfi_getsymval(ctx, smMacro_if_addr)) == NULL)
		if_addr = "0.0.0.0";

#ifdef DROPPED_ADD_HEADERS
	if (optAddHeaders) {
		/* Add trace to the message. There can be many of these, one
		 * for each filter/host that looks at the message.
		 */
		length = snprintf(data->line, sizeof (data->line), MILTER_STRING " (%s [%s]); ", if_name, if_addr);
		length += TimeStampAdd(data->line + length, sizeof (data->line) - length);
		(void) smfi_addheader(ctx, X_SCANNED_BY, data->line);
	}
#endif
	if (optReceivedSpfHeaders.value) {
		length = snprintf(data->line, sizeof (data->line), "%s", spfResultString[data->spfHelo]);
		if (data->spfHeloError != NULL && data->spfHeloError != smfUndefined)
			length += snprintf(data->line+length, sizeof (data->line)-length, " (%s)", data->spfHeloError);
		snprintf(
			data->line+length, sizeof (data->line)-length,
			"; receiver=%s; client-ip=%s; helo=%s",
			if_name, data->client_addr, data->helo
		);
		(void) smfi_addheader(ctx, RECEIVED_SPF, data->line);

		length = snprintf(data->line, sizeof (data->line), "%s", spfResultString[data->spfMail]);
		if (data->spfMailError != NULL && data->spfMailError != smfUndefined)
			length += snprintf(data->line+length, sizeof (data->line)-length, " (%s)", data->spfMailError);
		snprintf(
			data->line+length, sizeof (data->line)-length,
			"; receiver=%s; client-ip=%s; envelope-from=<%s>",
			if_name, data->client_addr, data->work.mail->address.string
		);
		(void) smfi_addheader(ctx, RECEIVED_SPF, data->line);
	}

	/* A white listed connection or sender should NOT tag or discard
	 * the message. Also any white listed recipient will white list
	 * for all recipients of the message.
	 */
	if (data->work.skipMessage)
		return SMFIS_CONTINUE;

	tag = 0;
	switch (spfAction(spfHelo, data->spfHelo)) {
	case X_SMFIS_TAG:
		tag = 1;
		break;
	case SMFIS_DISCARD:
		smfLog(
			SMF_LOG_INFO, TAG_FORMAT "HELO %s from %s SPF result %s, discarding",
			TAG_ARGS, data->helo, data->client_addr, spfResultString[data->spfHelo]
		);
		return SMFIS_DISCARD;
	}

	switch (spfAction(spfMail, data->spfMail)) {
	case X_SMFIS_TAG:
		tag = 1;
		break;
	case SMFIS_DISCARD:
		smfLog(
			SMF_LOG_INFO, TAG_FORMAT "sender <%s> via %s SPF result %s, discarding",
			TAG_ARGS, data->work.mail->address.string, data->client_addr, spfResultString[data->spfMail]
		);
		return SMFIS_DISCARD;
	}

	if (tag && TextInsensitiveStartsWith(data->subject, optSubjectTag.string) < 0) {
		(void) snprintf(data->line, sizeof (data->line), "%s %s", optSubjectTag.string, data->subject);
		(void) smfHeaderSet(data->work.ctx, "Subject", data->line, 1, data->hasSubject);
	}

	return SMFIS_CONTINUE;
}

/*
 * Close and release per-connection resources.
 */
static sfsistat
filterClose(SMFICTX *ctx)
{
	workspace data;
	unsigned short cid = 0;

	if ((data = (workspace) smfi_getpriv(ctx)) != NULL) {
		cid = smfCloseEpilog(&data->work);
		free(data);
	}

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterClose(%lx)", cid, smfNoQueue, (long) ctx);

	return SMFIS_CONTINUE;
}


/***********************************************************************
 ***  Milter Definition Block
 ***********************************************************************/

static smfInfo milter = {
	MILTER_MAJOR,
	MILTER_MINOR,
	MILTER_BUILD,
	MILTER_NAME,
	MILTER_AUTHOR,
	MILTER_COPYRIGHT,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	SMF_STDIO_CLOSE,

	/* struct smfiDesc */
	{
		MILTER_NAME,		/* filter name */
		SMFI_VERSION,		/* version code -- do not change */
		SMFIF_ADDHDRS|SMFIF_CHGHDRS,		/* flags */
		filterOpen,		/* connection info filter */
		filterHelo,		/* SMTP HELO command filter */
		filterMail,		/* envelope sender filter */
		filterRcpt,		/* envelope recipient filter */
		filterHeader,		/* header filter */
		NULL,			/* end of header */
		NULL,			/* body block filter */
		filterEndMessage,	/* end of message */
		NULL,			/* message aborted */
		filterClose		/* connection cleanup */
#if SMFI_VERSION > 2
		, NULL			/* Unknown/unimplemented commands */
#endif
#if SMFI_VERSION > 3
		, NULL			/* SMTP DATA command */
#endif
	}
};

/***********************************************************************
 *** Startup
 ***********************************************************************/

void
atExitCleanUp()
{
	smdbClose(smdbAccess);
	smfAtExitCleanUp();
}

int
main(int argc, char **argv)
{
	int argi;

	/* Defaults */
	smfOptFile.initial = MILTER_CF;
	smfOptPidFile.initial = PID_FILE;
	smfOptRunUser.initial = RUN_AS_USER;
	smfOptRunGroup.initial = RUN_AS_GROUP;
	smfOptWorkDir.initial = WORK_DIR;
	smfOptMilterSocket.initial = "unix:" SOCKET_FILE;

	/* Parse command line options looking for a file= option. */
	optionInit(optTable, smfOptTable, NULL);
	argi = optionArrayL(argc, argv, optTable, smfOptTable, NULL);

	/* Parse the option file followed by the command line options again. */
	if (smfOptFile.string != NULL && *smfOptFile.string != '\0') {
		/* Do NOT reset this option. */
		smfOptFile.initial = smfOptFile.string;
		smfOptFile.string = NULL;

		optionInit(optTable, smfOptTable, NULL);
		(void) optionFile(smfOptFile.string, optTable, smfOptTable, NULL);
		(void) optionArrayL(argc, argv, optTable, smfOptTable, NULL);
	}

	/* Show them the funny farm. */
	if (smfOptHelp.string != NULL) {
		optionUsageL(optTable, smfOptTable, NULL);
		exit(2);
	}

	if (smfOptQuit.string != NULL) {
		/* Use SIGQUIT signal in order to avoid delays
		 * caused by libmilter's handling of SIGTERM.
		 * smfi_stop() takes too long since it waits
		 * for connections to terminate, which could
		 * be a several minutes or longer.
		 */
		exit(pidKill(smfOptPidFile.string, SIGQUIT) != 0);
	}

	if (smfOptRestart.string != NULL) {
		(void) pidKill(smfOptPidFile.string, SIGQUIT);
		sleep(2);
	}

	if (smfOptDaemon.value && smfStartBackgroundProcess())
		return 1;

	(void) smfi_settimeout((int) smfOptMilterTimeout.value);
	(void) smfSetLogDetail(smfOptVerbose.string);

	spfHelo = setBitWord(result_action_words, optHeloPolicy.string);
	spfMail = setBitWord(result_action_words, optMailPolicy.string);

	if ((spfHelo & (SPIFF_FAIL_TAG|SPIFF_SOFTFAIL_TAG)) == 0
	&&  (spfMail & (SPIFF_FAIL_TAG|SPIFF_SOFTFAIL_TAG)) == 0)
		milter.handlers.xxfi_flags &= ~SMFIF_CHGHDRS;

#ifdef DROPPED_ADD_HEADERS
	if (!optAddHeaders.value && !optReceivedSpfHeaders.value)
#else
	if (!optReceivedSpfHeaders.value)
#endif
		milter.handlers.xxfi_flags &= ~SMFIF_ADDHDRS;

	pdqMaxTimeout(optDnsMaxTimeout.value);
	pdqSetRoundRobin(optDnsRoundRobin.value);
	if (smfLogDetail & SMF_LOG_DNS) {
		pdqSetDebug(1);
		spfSetDebug(1);
	}

	openlog(MILTER_NAME, LOG_PID, LOG_MAIL);

	if (atexit(atExitCleanUp)) {
		syslog(LOG_ERR, "atexit() failed\n");
		return 1;
	}

	if (*smfOptAccessDb.string != '\0') {
		if (smfLogDetail & SMF_LOG_DATABASE)
			smdbSetDebugMask(SMDB_DEBUG_ALL);

		if ((smdbAccess = smdbOpen(smfOptAccessDb.string, 1)) == NULL) {
			syslog(LOG_ERR, "failed to open \"%s\"", smfOptAccessDb.string);
			return 1;
		}
	}

	return smfMainStart(&milter);
}
