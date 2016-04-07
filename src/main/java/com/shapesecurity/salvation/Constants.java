package com.shapesecurity.salvation;

import java.util.regex.Pattern;

@SuppressWarnings("MalformedRegex") public class Constants {
    public static final String schemePart = "[a-zA-Z][a-zA-Z0-9+\\-.]*";
    public static final Pattern referrerTokenPattern = Pattern
        .compile("^(?:no-referrer|no-referrer-when-downgrade|origin" + "|origin-when-cross-origin|unsafe-url)$",
            Pattern.CASE_INSENSITIVE);
    public static final Pattern rfc7230TokenPattern = Pattern.compile("^[!#$%&'*+\\-.^_`|~0-9a-zA-Z]+$");
    public static final Pattern sandboxEnumeratedTokenPattern = Pattern.compile(
        "^allow-(?:forms|modals|pointer-lock" + "|popups|popups-to-escape-sandbox|same-origin"
            + "|scripts|top-navigation)$");
    public static final Pattern mediaTypePattern = Pattern.compile("^(?<type>[^/]+)/(?<subtype>[^/]+)$");
    public static final Pattern unquotedKeywordPattern = Pattern.compile("^(?:self|unsafe-inline|unsafe-eval|unsafe-redirect|none)$");
    // port-part constants
    public static final int WILDCARD_PORT = -200;
    public static final int EMPTY_PORT = -1;
    private static final String hostPart = "\\*|(?:\\*\\.)?[a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)*";
    private static final String portPart = ":(?:[0-9]+|\\*)";
    private static final String unreserved = "[a-zA-Z0-9\\-._~]";
    private static final String pctEncoded = "%[a-fA-F0-9]{2}";
    private static final String subDelims = "[!$&'()*+,;=]";
    private static final String pchar = "(?:" + unreserved + "|" + pctEncoded + "|" + subDelims + "|[:@])";
    // XXX: divergence from spec; uses path-abempty from RFC3986 instead of path
    private static final String pathPart = "(?:/" + pchar + "*)+";
    private static final String queryFragmentPart = "(?:\\?[^#]*)?(?:#.*)?";
    public static final Pattern hostSourcePattern = Pattern.compile(
        "^(?<scheme>" + schemePart + "://)?(?<host>" + hostPart + ")(?<port>" + portPart + ")?(?<path>" + pathPart
            + ")?" + queryFragmentPart + "$");
    public static final Pattern relativeReportUriPattern =
        Pattern.compile("^(?<path>" + pathPart + ")" + queryFragmentPart + "$");

}
