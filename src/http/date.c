/* The Date header value, built by hand (strftime depends on the locale) and cached for a second. */
#include "http/stream.h"

#include <stdio.h>
#include <time.h>

static const char *const days[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
static const char *const months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
				      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

size_t bst_http_date_format(time_t t, char out[BST_HTTP_DATE_LEN + 1])
{
	struct tm tm;
	if (gmtime_r(&t, &tm) == NULL) {
		out[0] = '\0';
		return 0;
	}
	/* RFC 9110 section 5.6.7, IMF-fixdate: Sun, 06 Nov 1994 08:49:37 GMT */
	int n = snprintf(out, BST_HTTP_DATE_LEN + 1, "%s, %02d %s %04d %02d:%02d:%02d GMT",
			 days[tm.tm_wday], tm.tm_mday, months[tm.tm_mon], tm.tm_year + 1900,
			 tm.tm_hour, tm.tm_min, tm.tm_sec);
	return n == BST_HTTP_DATE_LEN ? (size_t)n : 0;
}

bst_str bst_http_date(void)
{
	static time_t cached_at = -1;
	static char cached[BST_HTTP_DATE_LEN + 1];
	time_t now = time(NULL);
	if (now != cached_at) {
		if (bst_http_date_format(now, cached) != BST_HTTP_DATE_LEN)
			return (bst_str){ NULL, 0 };
		cached_at = now;
	}
	return (bst_str){ cached, BST_HTTP_DATE_LEN };
}
