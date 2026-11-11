/* The Date header value, built by hand (strftime depends on the locale) and cached for a second. */
#include "http/stream.h"

#include <stdio.h>
#include <time.h>

static const char *const days[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
static const char *const months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
				      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

size_t bst_http_date_format(time_t t, char out[BST_HTTP_DATE_LEN + 1])
{
	/*
	 * Civil-from-days by hand. glibc's gmtime_r initialises the timezone
	 * database on first use, which opens /etc/localtime, and the worker's
	 * seccomp filter rightly kills that openat.
	 */
	if (t < 0 || t > 253402300799) { /* 0000..9999 years only */
		out[0] = '\0';
		return 0;
	}
	long long secs = (long long)t;
	long long z = secs / 86400 + 719468;
	long long sod = secs % 86400;
	long long era = z / 146097;
	long long doe = z - era * 146097;
	long long yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
	long long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	long long mp = (5 * doy + 2) / 153;
	int mday = (int)(doy - (153 * mp + 2) / 5 + 1);
	int mon = (int)(mp < 10 ? mp + 3 : mp - 9); /* 1..12 */
	int year = (int)(yoe + era * 400 + (mon <= 2));
	int wday = (int)(((secs / 86400) + 4) % 7); /* 1970-01-01 was a Thursday */
	/* RFC 9110 section 5.6.7, IMF-fixdate: Sun, 06 Nov 1994 08:49:37 GMT */
	int n = snprintf(out, BST_HTTP_DATE_LEN + 1, "%s, %02d %s %04d %02d:%02d:%02d GMT",
			 days[wday], mday, months[mon - 1], year, (int)(sod / 3600),
			 (int)(sod % 3600 / 60), (int)(sod % 60));
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
