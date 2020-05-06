package com.shapesecurity.salvation2;

import java.util.regex.Pattern;

@SuppressWarnings("MalformedRegex")
public class Constants {
	// https://tools.ietf.org/html/rfc3986#section-3.1
	public static final String schemePart = "[a-zA-Z][a-zA-Z0-9+\\-.]*";
	public static final Pattern schemePattern = Pattern.compile("^(?<scheme>" + Constants.schemePart + ":)");

	// https://tools.ietf.org/html/rfc7230#section-3.2.6
	public static final Pattern rfc7230TokenPattern = Pattern.compile("^[!#$%&'*+\\-.^_`|~0-9a-zA-Z]+$");

	// RFC 2045 appendix A: productions of type and subtype
	// https://tools.ietf.org/html/rfc2045#section-5.1
	public static final Pattern mediaTypePattern = Pattern.compile("^(?<type>[a-zA-Z0-9!#$%^&*\\-_+{}|'.`~]+)/(?<subtype>[a-zA-Z0-9!#$%^&*\\-_+{}|'.`~]+)$");
	public static final Pattern unquotedKeywordPattern = Pattern.compile("^(?:self|unsafe-inline|unsafe-eval|unsafe-redirect|none|strict-dynamic|unsafe-hashes|report-sample|unsafe-allow-redirects)$");

	// port-part constants
	public static final int WILDCARD_PORT = -200;
	public static final int EMPTY_PORT = -1;

	// https://w3c.github.io/webappsec-csp/#grammardef-host-part
	private static final String hostPart = "\\*|(?:\\*\\.)?[a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)*";

	// https://w3c.github.io/webappsec-csp/#grammardef-port-part
	private static final String portPart = ":(?:[0-9]+|\\*)";
	private static final String unreserved = "[a-zA-Z0-9\\-._~]";
	private static final String pctEncoded = "%[a-fA-F0-9]{2}";
	private static final String subDelims = "[!$&'()*+,;=]";
	private static final String pchar = "(?:" + unreserved + "|" + pctEncoded + "|" + subDelims + "|[:@])";

	// https://w3c.github.io/webappsec-csp/#grammardef-path-part
	// XXX: divergence from spec; uses path-abempty from RFC3986 instead of path
	private static final String pathPart = "(?:/" + pchar + "*)+";

	private static final String queryFragmentPart = "(?:\\?[^#]*)?(?:#.*)?";

	public static final Pattern hostSourcePattern = Pattern.compile(
			"^(?<scheme>" + schemePart + "://)?(?<host>" + hostPart + ")(?<port>" + portPart + ")?(?<path>" + pathPart
					+ ")?" + queryFragmentPart + "$");
	//	public static final Pattern relativeReportUriPattern =
	//			Pattern.compile("^(?<path>" + pathPart + ")" + queryFragmentPart + "$");
	public static final Pattern IPv4address = Pattern.compile("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
	public static final Pattern IPV6loopback = Pattern.compile("^[0:]+:1$");
	public static final String IPv6address = "(?:(?:(?:[0-9A-Fa-f]{1,4}:){6}|::(?:[0-9A-Fa-f]{1,4}:){5}|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}|(?:(?:[0-9A-Fa-f]{1,4}:){0,1}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}|(?:(?:[0-9A-Fa-f]{1,4}:){0,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}|(?:(?:[0-9A-Fa-f]{1,4}:){0,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:|(?:(?:[0-9A-Fa-f]{1,4}:){0,4}[0-9A-Fa-f]{1,4})?::)(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4})?::)";
	public static final Pattern IPv6addressWithOptionalBracket = Pattern.compile("^(?:\\[" + IPv6address + "\\]|" + IPv6address + ")$");

	// https://infra.spec.whatwg.org/#ascii-whitespace
	public static String WHITESPACE_CHARS = "\t\n\f\r ";
}
