package com.shapesecurity.csp;

import com.shapesecurity.csp.Tokeniser.TokeniserException;
import com.shapesecurity.csp.directives.*;
import com.shapesecurity.csp.directives.SandboxDirective.SandboxToken;
import com.shapesecurity.csp.sources.*;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Parser {

    @Nonnull
    public static Policy parse(@Nonnull String sourceText) throws ParseException, TokeniserException {
        return new Parser(Tokeniser.tokenise(sourceText)).parse();
    }

    private static final String schemePart = "[a-zA-Z][a-zA-Z0-9+\\-.]*";
    private static final String hostPart = "\\*|(?:\\*\\.)?[a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)*";
    private static final String portPart = ":(?:[0-9]+|\\*)";
    private static final String unreserved = "[a-zA-Z0-9\\-._~]";
    private static final String pctEncoded = "%[a-fA-F0-9]{2}";
    private static final String subDelims = "[!$&'()*+,;=]";
    private static final String pchar = "(?:" + unreserved + "|" + pctEncoded + "|" + subDelims + "|[:@])";
    // XXX: divergence from spec; uses path-abempty from RFC3986 instead of path
    private static final String pathPart = "(?:/" + pchar + "*)*";
    private static final Pattern hostSourcePattern = Pattern.compile("^(?<scheme>" + schemePart + "://)?(?<host>" + hostPart + ")(?<port>" + portPart + ")?(?<path>" + pathPart + ")?$");
    private static final Pattern sandboxTokenPattern = Pattern.compile("^[!#$%&'*+\\-.^_`|~0-9a-zA-Z]+$");
    private static final Pattern uriPattern = Pattern.compile("^(?:(?:[^:/?#]+):)?(?://(?:[^/?#]*))?(?:[^?#]+)(?:\\?(?:[^#]*))?(?:#(?:.*))?");
    private static final Pattern mediaTypePattern = Pattern.compile("^(?<type>[^/]+)/(?<subtype>[^/]+)$");

    @Nonnull
    private final String[] tokens;
    private int index = 0;

    private Parser(@Nonnull String[] tokens) {
        this.tokens = tokens;
    }


    @Nonnull
    private String advance() {
        return this.tokens[this.index++];
    }

    private boolean hasNext() {
        return this.index < this.tokens.length;
    }

    private boolean hasNext(@Nonnull String token) {
        return this.hasNext() && token.equals(this.tokens[this.index]);
    }

    private boolean eat(@Nonnull String token) {
        if (this.hasNext(token)) {
            this.advance();
            return true;
        }
        return false;
    }

    @Nonnull
    private ParseException createError(@Nonnull String message) {
        return new ParseException(message);
    }

    @Nonnull
    private Policy parse() throws ParseException {
        Policy policy = new Policy();
        while (this.hasNext()) {
            if (this.eat(";")) continue;
            policy.addDirective(this.parseDirective());
            if (!this.eat(";")) {
                if (this.hasNext()) {
                    throw this.createError("expecting semicolon or end of policy but found " + this.advance());
                } else {
                    break;
                }
            }
        }
        return policy;
    }

    @Nonnull
    private Directive<?> parseDirective() throws ParseException {
        String token = this.advance();
        switch (token.toLowerCase()) {
            case "base-uri":
                return new BaseUriDirective(this.parseSourceList());
            case "child-src":
                return new ChildSrcDirective(this.parseSourceList());
            case "connect-src":
                return new ConnectSrcDirective(this.parseSourceList());
            case "default-src":
                return new DefaultSrcDirective(this.parseSourceList());
            case "font-src":
                return new FontSrcDirective(this.parseSourceList());
            case "form-action":
                return new FormActionDirective(this.parseSourceList());
            case "frame-ancestors":
                return new FrameAncestorsDirective(this.parseAncestorSourceList());
            case "frame-src":
                return new FrameSrcDirective(this.parseSourceList());
            case "img-src":
                return new ImgSrcDirective(this.parseSourceList());
            case "media-src":
                return new MediaSrcDirective(this.parseSourceList());
            case "object-src":
                return new ObjectSrcDirective(this.parseSourceList());
            case "plugin-types":
                return new PluginTypesDirective(this.parseMediaTypeList());
            case "report-uri":
                return new ReportUriDirective(this.parseUriList());
            case "sandbox":
                return new SandboxDirective(this.parseSandboxTokenList());
            case "script-src":
                return new ScriptSrcDirective(this.parseSourceList());
            case "style-src":
                return new StyleSrcDirective(this.parseSourceList());
            default:
                throw this.createError("expecting directive-name but found " + token);
        }
    }

    @Nonnull
    private List<MediaTypeListDirective.MediaType> parseMediaTypeList() throws ParseException {
        ArrayList<MediaTypeListDirective.MediaType> mediaTypes = new ArrayList<>();
        if (!this.hasNext() || this.hasNext(";")) {
            throw this.createError("media-type-list must contain at least one media-type");
        }
        mediaTypes.add(this.parseMediaType());
        while (this.hasNext() && !this.hasNext(";")) {
            mediaTypes.add(this.parseMediaType());
        }
        return mediaTypes;
    }

    @Nonnull
    private MediaTypeListDirective.MediaType parseMediaType() throws ParseException {
        String token = this.advance();
        Matcher matcher = mediaTypePattern.matcher(token);
        if (matcher.find()) {
            return new MediaTypeListDirective.MediaType(matcher.group("type"), matcher.group("subtype"));
        }
        throw this.createError("expecting media-type but found " + token);
    }

    @Nonnull
    private List<SourceExpression> parseSourceList() throws ParseException {
        ArrayList<SourceExpression> sourceExpressions = new ArrayList<>();
        if (this.eat("'none'")) {
            sourceExpressions.add(None.INSTANCE);
            return sourceExpressions;
        }
        while (this.hasNext() && !this.hasNext(";")) {
            sourceExpressions.add(this.parseSourceExpression());
        }
        return sourceExpressions;
    }

    @Nonnull
    private SourceExpression parseSourceExpression() throws ParseException {
        String token = this.advance();
        switch (token) {
            case "'self'":
                return KeywordSource.Self;
            case "'unsafe-inline'":
                return KeywordSource.UnsafeInline;
            case "'unsafe-eval'":
                return KeywordSource.UnsafeEval;
            case "'unsafe-redirect'":
                return KeywordSource.UnsafeRedirect;
            default:
                if (token.startsWith("'nonce-")) {
                    Base64Value b;
                    try {
                        b = new Base64Value(token.substring(7, token.length() - 1));
                    } catch (Base64Value.IllegalArgumentException | StringIndexOutOfBoundsException e) {
                        throw this.createError(e.getMessage());
                    }
                    return new NonceSource(b);
                } else if (token.startsWith("'sha")) {
                    HashSource.HashAlgorithm algo;
                    switch (token.substring(4, 7)) {
                        case "256":
                            algo = HashSource.HashAlgorithm.SHA256;
                            break;
                        case "384":
                            algo = HashSource.HashAlgorithm.SHA384;
                            break;
                        case "512":
                            algo = HashSource.HashAlgorithm.SHA512;
                            break;
                        default:
                            throw this.createError("unrecognised hash algorithm " + token.substring(1, 7));
                    }
                    Base64Value b;
                    try {
                        b = new Base64Value(token.substring(8, token.length() - 1));
                    } catch (Base64Value.IllegalArgumentException e) {
                        throw this.createError(e.getMessage());
                    }
                    return new HashSource(algo, b);
                } else if (token.matches("^" + schemePart + ":$")) {
                    return new SchemeSource(token.substring(0, token.length() - 1));
                } else {
                    Matcher matcher = hostSourcePattern.matcher(token);
                    if (matcher.find()) {
                        String scheme = matcher.group("scheme");
                        if (scheme != null) scheme = scheme.substring(0, scheme.length() - 3);
                        String port = matcher.group("port");
                        if (port != null) port = port.substring(1, port.length());
                        String host = matcher.group("host");
                        String path = matcher.group("path");
                        return new HostSource(scheme, host, port, path);
                    }
                }
        }
        throw this.createError("expecting source-expression but found " + token);
    }

    @Nonnull
    private List<AncestorSource> parseAncestorSourceList() throws ParseException {
        ArrayList<AncestorSource> ancestorSources = new ArrayList<>();
        if (this.hasNext("'none'")) {
            this.advance();
            ancestorSources.add(None.INSTANCE);
            return ancestorSources;
        }
        while (this.hasNext() && !this.hasNext(";")) {
            ancestorSources.add(this.parseAncestorSource());
        }
        return ancestorSources;
    }

    @Nonnull
    private AncestorSource parseAncestorSource() throws ParseException {
        String token = this.advance();
        if (token.matches("^" + schemePart + ":$")) {
            return new SchemeSource(token.substring(0, token.length() - 1));
        } else {
            Matcher matcher = hostSourcePattern.matcher(token);
            if (matcher.find()) {
                String scheme = matcher.group("scheme");
                if (scheme != null) scheme = scheme.substring(0, scheme.length() - 3);
                String port = matcher.group("port");
                if (port != null) port = port.substring(1, port.length());
                String host = matcher.group("host");
                String path = matcher.group("path");
                return new HostSource(scheme, host, port, path);
            }
        }
        throw this.createError("expecting ancestor-source but found " + token);
    }

    @Nonnull
    private List<SandboxToken> parseSandboxTokenList() throws ParseException {
        ArrayList<SandboxToken> sandboxTokens = new ArrayList<>();
        while (this.hasNext() && !this.hasNext(";")) {
            sandboxTokens.add(this.parseSandboxToken());
        }
        return sandboxTokens;
    }

    @Nonnull
    private SandboxToken parseSandboxToken() throws ParseException {
        String token = this.advance();
        Matcher matcher = sandboxTokenPattern.matcher(token);
        if (matcher.find()) {
            return new SandboxToken(token);
        }
        throw this.createError("expecting sandbox-token but found " + token);
    }

    @Nonnull
    private List<ReportUriDirective.URI> parseUriList() throws ParseException {
        ArrayList<ReportUriDirective.URI> uriList = new ArrayList<>();
        while (this.hasNext() && !this.hasNext(";")) {
            uriList.add(this.parseUri());
        }
        if (uriList.isEmpty()) {
            throw this.createError("report-uri must contain at least one uri-reference");
        }
        return uriList;
    }

    @Nonnull
    private ReportUriDirective.URI parseUri() throws ParseException {
        String token = this.advance();
        Matcher matcher = uriPattern.matcher(token);
        if (matcher.find()) {
            return new ReportUriDirective.URI(token);
        }
        throw this.createError("expecting uri-reference but found " + token);
    }

    public static class ParseException extends Exception {
        private ParseException(@Nonnull String message) {
            super(message);
        }
    }
}
