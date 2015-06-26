package com.shapesecurity.csp;

import java.util.regex.Pattern;

@SuppressWarnings("MalformedRegex")
public class Utils {
    public static final String schemePart = "[a-zA-Z][a-zA-Z0-9+\\-.]*";
    public static final String hostPart = "\\*|(?:\\*\\.)?[a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)*";
    public static final String portPart = ":(?:[0-9]+|\\*)";
    public static final String unreserved = "[a-zA-Z0-9\\-._~]";
    public static final String pctEncoded = "%[a-fA-F0-9]{2}";
    public static final String subDelims = "[!$&'()*+,;=]";
    public static final String pchar = "(?:" + unreserved + "|" + pctEncoded + "|" + subDelims + "|[:@])";
    // XXX: divergence from spec; uses path-abempty from RFC3986 instead of path
    public static final String pathPart = "(?:/" + pchar + "*)*";
    public static final Pattern hostSourcePattern = Pattern.compile("^(?<scheme>" + schemePart + "://)?(?<host>" + hostPart + ")(?<port>" + portPart + ")?(?<path>" + pathPart + ")?(?:\\?.*)?$");
    public static final Pattern sandboxTokenPattern = Pattern.compile("^[!#$%&'*+\\-.^_`|~0-9a-zA-Z]+$");
    public static final Pattern uriPattern = Pattern.compile("^(?:(?:[^:/?#]+):)?(?://(?:[^/?#]*))?(?:[^?#]+)(?:\\?(?:[^#]*))?(?:#(?:.*))?");
    public static final Pattern mediaTypePattern = Pattern.compile("^(?<type>[^/]+)/(?<subtype>[^/]+)$");
}
