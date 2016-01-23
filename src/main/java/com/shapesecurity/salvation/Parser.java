package com.shapesecurity.salvation;

import com.shapesecurity.salvation.data.*;
import com.shapesecurity.salvation.directiveValues.*;
import com.shapesecurity.salvation.directives.*;
import com.shapesecurity.salvation.tokens.*;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Parser {

    private static final Pattern WSP = Pattern.compile("[ \t]+");
    private static final Pattern NotWSP = Pattern.compile("[^ \t]+");
    private static final DirectiveParseException MISSING_DIRECTIVE_NAME =
        new DirectiveParseException("Missing directive-name");
    private static final DirectiveParseException INVALID_DIRECTIVE_NAME =
        new DirectiveParseException("Invalid directive-name");
    private static final DirectiveParseException INVALID_DIRECTIVE_VALUE =
        new DirectiveParseException("Invalid directive-value");
    private static final DirectiveParseException INVALID_MEDIA_TYPE_LIST =
        new DirectiveParseException("Invalid media-type-list");
    private static final DirectiveValueParseException INVALID_MEDIA_TYPE =
        new DirectiveValueParseException("Invalid media-type");
    private static final DirectiveParseException INVALID_SOURCE_LIST =
        new DirectiveParseException("Invalid source-list");
    private static final DirectiveValueParseException INVALID_SOURCE_EXPR =
        new DirectiveValueParseException("Invalid source-expression");
    private static final DirectiveParseException INVALID_ANCESTOR_SOURCE_LIST =
        new DirectiveParseException("Invalid ancestor-source-list");
    private static final DirectiveParseException INVALID_REFERRER_TOKEN_LIST =
        new DirectiveParseException("Invalid referrer-token list");
    private static final DirectiveParseException INVALID_SANDBOX_TOKEN_LIST =
        new DirectiveParseException("Invalid sandbox-token list");
    private static final DirectiveParseException INVALID_URI_REFERENCE_LIST =
        new DirectiveParseException("Invalid uri-reference list");
    private static final DirectiveParseException NON_EMPTY_VALUE_TOKEN_LIST =
        new DirectiveParseException("Non-empty directive-value list");
    @Nonnull protected final Token[] tokens;
    @Nonnull private final Origin origin;
    protected int index = 0;
    @Nullable protected Collection<Notice> noticesOut;

    protected Parser(@Nonnull Token[] tokens, @Nonnull Origin origin, @Nullable Collection<Notice> noticesOut) {
        this.origin = origin;
        this.tokens = tokens;
        this.noticesOut = noticesOut;
    }

    @Nonnull public static Policy parse(@Nonnull String sourceText, @Nonnull Origin origin) {
        return new Parser(Tokeniser.tokenise(sourceText), origin, null).parsePolicyAndAssertEOF();
    }

    @Nonnull public static Policy parse(@Nonnull String sourceText, @Nonnull String origin) {
        return new Parser(Tokeniser.tokenise(sourceText), URI.parse(origin), null).parsePolicyAndAssertEOF();
    }

    @Nonnull public static Policy parse(@Nonnull String sourceText, @Nonnull Origin origin,
        @Nonnull Collection<Notice> warningsOut) {
        return new Parser(Tokeniser.tokenise(sourceText), origin, warningsOut).parsePolicyAndAssertEOF();
    }

    @Nonnull public static Policy parse(@Nonnull String sourceText, @Nonnull String origin,
        @Nonnull Collection<Notice> warningsOut) {
        return new Parser(Tokeniser.tokenise(sourceText), URI.parse(origin), warningsOut).parsePolicyAndAssertEOF();
    }

    @Nonnull public static List<Policy> parseMulti(@Nonnull String sourceText, @Nonnull Origin origin) {
        return new Parser(Tokeniser.tokenise(sourceText), origin, null).parsePolicyListAndAssertEOF();
    }

    @Nonnull public static List<Policy> parseMulti(@Nonnull String sourceText, @Nonnull String origin) {
        return new Parser(Tokeniser.tokenise(sourceText), URI.parse(origin), null).parsePolicyListAndAssertEOF();
    }

    @Nonnull public static List<Policy> parseMulti(@Nonnull String sourceText, @Nonnull Origin origin,
        @Nonnull Collection<Notice> warningsOut) {
        return new Parser(Tokeniser.tokenise(sourceText), origin, warningsOut).parsePolicyListAndAssertEOF();
    }

    @Nonnull public static List<Policy> parseMulti(@Nonnull String sourceText, @Nonnull String origin,
        @Nonnull Collection<Notice> warningsOut) {
        return new Parser(Tokeniser.tokenise(sourceText), URI.parse(origin), warningsOut).parsePolicyListAndAssertEOF();
    }

    @Nonnull private static String trimRHSWS(@Nonnull String s) {
        int i;
        for (i = s.length() - 1; i >= 0; --i) {
            int c = s.codePointAt(i);
            if (WSP.matcher(new String(new int[]{c}, 0, 1)).find())
                break;
        }
        return s.substring(0, i + 1);
    }

    @Nonnull protected Notice createNotice(@Nonnull Notice.Type type, @Nonnull String message) {
        return new Notice(type, message);
    }

    @Nonnull protected Notice createNotice(@Nullable Token token, @Nonnull Notice.Type type, @Nonnull String message) {
        return new Notice(type, message);
    }

    private void warn(@Nonnull String message) {
        this.warn(this.getCurrentToken(), message);
    }

    private void warn(@Nullable Token token, @Nonnull String message) {
        if (this.noticesOut != null) {
            this.noticesOut.add(this.createNotice(token, Notice.Type.WARNING, message));
        }
    }

    private void error(@Nonnull String message) {
        this.error(this.getCurrentToken(), message);
    }

    private void error(@Nullable Token token, @Nonnull String message) {
        if (this.noticesOut != null) {
            this.noticesOut.add(this.createNotice(token, Notice.Type.ERROR, message));
        }
    }

    private void info(@Nonnull String message) {
        this.info(this.getCurrentToken(), message);
    }

    private void info(@Nullable Token token, @Nonnull String message) {
        if (this.noticesOut != null) {
            this.noticesOut.add(this.createNotice(token, Notice.Type.INFO, message));
        }
    }

    @Nullable protected Token getCurrentToken() {
        return this.index <= this.tokens.length && this.index > 0 ? this.tokens[this.index - 1] : null;
    }

    @Nonnull private Token advance() {
        return this.tokens[this.index++];
    }

    protected boolean hasNext() {
        return this.index < this.tokens.length;
    }

    private boolean hasNext(@Nonnull Class<? extends Token> c) {
        return this.hasNext() && c.isAssignableFrom(this.tokens[this.index].getClass());
    }

    private boolean eat(@Nonnull Class<? extends Token> c) {
        if (this.hasNext(c)) {
            this.advance();
            return true;
        }
        return false;
    }

    @Nonnull protected DirectiveValueParseException createError(@Nonnull String message) {
        return new DirectiveValueParseException(message);
    }

    @Nonnull protected DirectiveValueParseException createError(@Nonnull Token token, @Nonnull String message) {
        return new DirectiveValueParseException(message);
    }

    @Nonnull protected Policy parsePolicy() {
        Policy policy = new Policy(this.origin);
        while (this.hasNext()) {
            if (this.hasNext(PolicySeparatorToken.class))
                break;
            if (this.eat(DirectiveSeparatorToken.class))
                continue;
            try {
                policy.addDirective(this.parseDirective());
            } catch (DirectiveParseException ignored) {
            }
        }
        return policy;
    }

    @Nonnull protected Policy parsePolicyAndAssertEOF() {
        Policy policy = this.parsePolicy();
        if (this.hasNext()) {
            this.error("Expecting end of policy but found " + this.advance().value);
        }
        return policy;
    }

    @Nonnull protected List<Policy> parsePolicyList() {
        List<Policy> policies = new ArrayList<>();
        policies.add(this.parsePolicy());
        while (this.hasNext(PolicySeparatorToken.class)) {
            while (this.eat(PolicySeparatorToken.class))
                ;
            policies.add(this.parsePolicy());
        }
        return policies;
    }

    @Nonnull protected List<Policy> parsePolicyListAndAssertEOF() {
        List<Policy> policies = this.parsePolicyList();
        if (this.hasNext()) {
            this.error("Expecting end of policy list but found " + this.advance().value);
        }
        return policies;
    }

    @Nonnull private Directive<?> parseDirective() throws DirectiveParseException {
        if (!this.hasNext(DirectiveNameToken.class)) {
            this.error("Expecting directive-name but found " + WSP.split(this.advance().value, 2)[0]);
            throw MISSING_DIRECTIVE_NAME;
        }
        Directive result;
        DirectiveNameToken token = (DirectiveNameToken) this.advance();
        switch (token.subtype) {
            case BaseUri:
                result = new BaseUriDirective(this.parseSourceList());
                break;
            case BlockAllMixedContent:
                this.enforceMissingDirectiveValue(token.value);
                result = new BlockAllMixedContentDirective();
                break;
            case ChildSrc:
                result = new ChildSrcDirective(this.parseSourceList());
                break;
            case ConnectSrc:
                result = new ConnectSrcDirective(this.parseSourceList());
                break;
            case DefaultSrc:
                result = new DefaultSrcDirective(this.parseSourceList());
                break;
            case FontSrc:
                result = new FontSrcDirective(this.parseSourceList());
                break;
            case FormAction:
                result = new FormActionDirective(this.parseSourceList());
                break;
            case FrameAncestors:
                result = new FrameAncestorsDirective(this.parseAncestorSourceList());
                break;
            case ImgSrc:
                result = new ImgSrcDirective(this.parseSourceList());
                break;
            case ManifestSrc:
                result = new ManifestSrcDirective(this.parseSourceList());
                break;
            case MediaSrc:
                result = new MediaSrcDirective(this.parseSourceList());
                break;
            case ObjectSrc:
                result = new ObjectSrcDirective(this.parseSourceList());
                break;
            case PluginTypes:
                result = new PluginTypesDirective(this.parseMediaTypeList());
                break;
            case Referrer:
                result = new ReferrerDirective(this.parseReferrerTokenList());
                break;
            case ReportUri:
                result = new ReportUriDirective(this.parseUriList());
                break;
            case Sandbox:
                result = new SandboxDirective(this.parseSandboxTokenList());
                break;
            case ScriptSrc:
                result = new ScriptSrcDirective(this.parseSourceList());
                break;
            case StyleSrc:
                result = new StyleSrcDirective(this.parseSourceList());
                break;
            case UpgradeInsecureRequests:
                this.enforceMissingDirectiveValue(token.value);
                result = new UpgradeInsecureRequestsDirective();
                break;
            case Allow:
                this.error(
                    "The allow directive has been replaced with default-src and is not in the CSP specification.");
                if (this.hasNext(DirectiveValueToken.class))
                    this.advance();
                throw INVALID_DIRECTIVE_NAME;
            case FrameSrc:
                this.warn(
                    "The frame-src directive is deprecated as of CSP version 1.1. Authors who wish to govern nested browsing contexts SHOULD use the child-src directive instead.");
                result = new FrameSrcDirective(this.parseSourceList());
                break;
            case Options:
                this.error(
                    "The options directive has been replaced with 'unsafe-inline' and 'unsafe-eval' and is not in the CSP specification.");
                if (this.hasNext(DirectiveValueToken.class))
                    this.advance();
                throw INVALID_DIRECTIVE_NAME;
            case Unrecognised:
            default:
                this.error("Unrecognised directive-name: " + token.value);
                if (this.hasNext(DirectiveValueToken.class))
                    this.advance();
                throw INVALID_DIRECTIVE_NAME;
        }
        if (this.hasNext(UnknownToken.class)) {
            int cp = this.advance().value.codePointAt(0);
            this.error(String.format(
                "Expecting directive-value but found U+%04X (%s). Non-ASCII and non-printable characters must be percent-encoded",
                cp, new String(new int[] {cp}, 0, 1)));
            throw INVALID_DIRECTIVE_VALUE;
        }
        return result;
    }

    private void enforceMissingDirectiveValue(@Nonnull String tokenValue) throws DirectiveParseException {
        if (this.eat(DirectiveValueToken.class)) {
            this.error("The " + tokenValue + " directive must not contain any value");
            throw NON_EMPTY_VALUE_TOKEN_LIST;
        }
    }

    @Nonnull private Set<MediaType> parseMediaTypeList() throws DirectiveParseException {
        Set<MediaType> mediaTypes = new LinkedHashSet<>();
        if (this.hasNext(DirectiveValueToken.class)) {
            boolean parseException = false;
            Token dv = this.advance();
            for (SubDirectiveValueToken subdv : splitByWSP(dv)) {
                try {
                    mediaTypes.add(this.parseMediaType(subdv));
                } catch (DirectiveValueParseException e) {
                    parseException = true;
                }
            }
            if (parseException) {
                throw INVALID_MEDIA_TYPE_LIST;
            }
        }
        if (mediaTypes.isEmpty()) {
            this.error("The media-type-list must contain at least one media-type");
            throw INVALID_MEDIA_TYPE_LIST;
        }
        return mediaTypes;
    }

    @Nonnull private MediaType parseMediaType(@Nonnull SubDirectiveValueToken token) throws DirectiveValueParseException {
        Matcher matcher = Constants.mediaTypePattern.matcher(token.value);
        if (matcher.find()) {
            return new MediaType(matcher.group("type"), matcher.group("subtype"));
        }
        this.error(token, "Expecting media-type but found " + token.value);
        throw INVALID_MEDIA_TYPE;
    }

    @Nonnull private Set<SourceExpression> parseSourceList() throws DirectiveParseException {
        Set<SourceExpression> sourceExpressions = new LinkedHashSet<>();
        if (this.hasNext(DirectiveValueToken.class)) {
            boolean parseException = false;
            Token dv = this.advance();
            if (trimRHSWS(dv.value).equalsIgnoreCase("'none'")) {
                sourceExpressions.add(None.INSTANCE);
                return sourceExpressions;
            }
            for (SubDirectiveValueToken subdv : splitByWSP(dv)) {
                try {
                    sourceExpressions.add(this.parseSourceExpression(subdv));
                } catch (DirectiveValueParseException e) {
                    parseException = true;
                }
            }
            if (parseException) {
                throw INVALID_SOURCE_LIST;
            }
        }
        return sourceExpressions;
    }

    @Nonnull
    private List<SubDirectiveValueToken> splitByWSP(@Nonnull Token token) {
        List<SubDirectiveValueToken> tokens = new ArrayList<>();
        @Nullable Location startLocation = token.startLocation;
        if (startLocation == null) {
            for (String s : WSP.split(token.value)) {
                tokens.add(new SubDirectiveValueToken(s));
            }
        } else {
            Matcher m = NotWSP.matcher(token.value);
            int offset = 0;
            while (m.find(offset)) {
                SubDirectiveValueToken dv = new SubDirectiveValueToken(token.value.substring(m.start(), m.end()));
                dv.startLocation = new Location(startLocation.line, startLocation.column + m.start(), startLocation.offset + m.start());
                dv.endLocation = new Location(startLocation.line, startLocation.column + m.end(), startLocation.offset + m.end());
                offset = m.end();
                tokens.add(dv);
            }
        }
        return tokens;
    }

    @Nonnull private SourceExpression parseSourceExpression(@Nonnull SubDirectiveValueToken token)
        throws DirectiveValueParseException {
        switch (token.value.toLowerCase()) {
            case "'none'":
                this.error(token, "'none' must not be combined with any other source-expression");
                throw INVALID_SOURCE_EXPR;
            case "'self'":
                return KeywordSource.Self;
            case "'unsafe-inline'":
                return KeywordSource.UnsafeInline;
            case "'unsafe-eval'":
                return KeywordSource.UnsafeEval;
            case "'unsafe-redirect'":
                this.warn(token, "'unsafe-redirect' has been removed from CSP as of version 2.0");
                return KeywordSource.UnsafeRedirect;
            case "self":
            case "unsafe-inline":
            case "unsafe-eval":
            case "unsafe-redirect":
            case "none":
                this.warn(token,
                    "This host name is unusual, and likely meant to be a keyword that is missing the required quotes: \'"
                        + token.value.toLowerCase() + "\'");
            default:
                if (token.value.startsWith("'nonce-")) {
                    String nonce = token.value.substring(7, token.value.length() - 1);
                    NonceSource nonceSource = new NonceSource(nonce);
                    nonceSource.validationErrors().forEach(this::warn);
                    return nonceSource;
                } else if (token.value.toLowerCase().startsWith("'sha")) {
                    HashSource.HashAlgorithm algorithm;
                    switch (token.value.substring(4, 7)) {
                        case "256":
                            algorithm = HashSource.HashAlgorithm.SHA256;
                            break;
                        case "384":
                            algorithm = HashSource.HashAlgorithm.SHA384;
                            break;
                        case "512":
                            algorithm = HashSource.HashAlgorithm.SHA512;
                            break;
                        default:
                            this.error(token, "Unrecognised hash algorithm " + token.value.substring(1, 7));
                            throw INVALID_SOURCE_EXPR;
                    }
                    String value = token.value.substring(8, token.value.length() - 1);
                    // convert url-safe base64 to RFC4648 base64
                    String safeValue = value.replace('-', '+').replace('_', '/');
                    Base64Value base64Value;
                    try {
                        base64Value = new Base64Value(safeValue);
                    } catch (IllegalArgumentException e) {
                        this.error(token, e.getMessage());
                        throw INVALID_SOURCE_EXPR;
                    }
                    // warn if value is not RFC4648
                    if (value.contains("-") || value.contains("_")) {
                        this.warn(token,
                            "Invalid base64-value (characters are not in the base64-value grammar). Consider using RFC4648 compliant base64 encoding implementation");
                    }
                    HashSource hashSource = new HashSource(algorithm, base64Value);
                    try {
                        hashSource.validationErrors();
                    } catch (IllegalArgumentException e) {
                        this.error(token, e.getMessage());
                        throw INVALID_SOURCE_EXPR;
                    }
                    return hashSource;
                } else if (token.value.matches("^" + Constants.schemePart + ":$")) {
                    return new SchemeSource(token.value.substring(0, token.value.length() - 1));
                } else {
                    Matcher matcher = Constants.hostSourcePattern.matcher(token.value);
                    if (matcher.find()) {
                        String scheme = matcher.group("scheme");
                        if (scheme != null)
                            scheme = scheme.substring(0, scheme.length() - 3);
                        String portString = matcher.group("port");
                        int port;
                        if (portString == null) {
                            port = scheme == null ?
                                Constants.EMPTY_PORT :
                                SchemeHostPortTriple.defaultPortForProtocol(scheme);
                        } else {
                            port = portString.equals(":*") ?
                                Constants.WILDCARD_PORT :
                                Integer.parseInt(portString.substring(1));
                        }
                        String host = matcher.group("host");
                        String path = matcher.group("path");
                        return new HostSource(scheme, host, port, path);
                    }
                }
        }
        this.error(token, "Expecting source-expression but found " + token.value);
        throw INVALID_SOURCE_EXPR;
    }

    @Nonnull private Set<AncestorSource> parseAncestorSourceList() throws DirectiveParseException {
        Set<AncestorSource> ancestorSources = new LinkedHashSet<>();
        if (this.hasNext(DirectiveValueToken.class)) {
            boolean parseException = false;
            String dv = trimRHSWS(this.advance().value);
            if (dv.equalsIgnoreCase("'none'")) {
                ancestorSources.add(None.INSTANCE);
                return ancestorSources;
            }
            for (String v : WSP.split(dv)) {
                try {
                    ancestorSources.add(this.parseAncestorSource(v));
                } catch (DirectiveValueParseException e) {
                    parseException = true;
                    this.error(e.getMessage());
                }
            }
            if (parseException) {
                throw INVALID_ANCESTOR_SOURCE_LIST;
            }
        }
        return ancestorSources;
    }

    @Nonnull private AncestorSource parseAncestorSource(@Nonnull String ancestorSource)
        throws DirectiveValueParseException {
        if (ancestorSource.equalsIgnoreCase("'none'")) {
            throw this.createError("The 'none' keyword must not be combined with any other source-expression");
        }
        if (ancestorSource.equalsIgnoreCase("'self'")) {
            return KeywordSource.Self;
        }
        if (ancestorSource.matches("^" + Constants.schemePart + ":$")) {
            return new SchemeSource(ancestorSource.substring(0, ancestorSource.length() - 1));
        } else {
            Matcher matcher = Constants.hostSourcePattern.matcher(ancestorSource);
            if (matcher.find()) {
                String scheme = matcher.group("scheme");
                if (scheme != null)
                    scheme = scheme.substring(0, scheme.length() - 3);
                String portString = matcher.group("port");
                int port;
                if (portString == null) {
                    port = scheme == null ? Constants.EMPTY_PORT : SchemeHostPortTriple.defaultPortForProtocol(scheme);
                } else {
                    port =
                        portString.equals(":*") ? Constants.WILDCARD_PORT : Integer.parseInt(portString.substring(1));
                }
                String host = matcher.group("host");
                String path = matcher.group("path");
                return new HostSource(scheme, host, port, path);
            }
        }
        throw this.createError("Expecting ancestor-source but found " + ancestorSource);
    }

    @Nonnull private Set<ReferrerValue> parseReferrerTokenList() throws DirectiveParseException {

        Set<ReferrerValue> referrerTokens = new LinkedHashSet<>();
        if (this.hasNext(DirectiveValueToken.class)) {
            boolean parseException = false;
            String dv = trimRHSWS(this.advance().value);
            for (String v : WSP.split(dv)) {
                try {
                    referrerTokens.add(this.parseReferrerToken(v));
                } catch (DirectiveValueParseException e) {
                    parseException = true;
                    this.error(e.getMessage());
                }
            }
            if (parseException) {
                throw INVALID_REFERRER_TOKEN_LIST;
            }
        }
        if (referrerTokens.size() != 1) {
            this.error("The referrer directive must contain exactly one referrer-token");
            throw INVALID_REFERRER_TOKEN_LIST;
        }
        return referrerTokens;
    }

    @Nonnull private ReferrerValue parseReferrerToken(@Nonnull String referrerToken)
        throws DirectiveValueParseException {
        Matcher matcher = Constants.referrerTokenPattern.matcher(referrerToken);
        if (matcher.find()) {
            return new ReferrerValue(referrerToken);
        }
        throw this.createError("Expecting referrer-token but found " + referrerToken);
    }

    @Nonnull private Set<SandboxValue> parseSandboxTokenList() throws DirectiveParseException {
        Set<SandboxValue> sandboxTokens = new LinkedHashSet<>();
        if (this.hasNext(DirectiveValueToken.class)) {
            boolean parseException = false;
            String dv = trimRHSWS(this.advance().value);
            for (String v : WSP.split(dv)) {
                try {
                    sandboxTokens.add(this.parseSandboxToken(v));
                } catch (DirectiveValueParseException e) {
                    parseException = true;
                    this.error(e.getMessage());
                }
            }
            if (parseException) {
                throw INVALID_SANDBOX_TOKEN_LIST;
            }
        }
        return sandboxTokens;
    }

    @Nonnull private SandboxValue parseSandboxToken(@Nonnull String sandboxToken) throws DirectiveValueParseException {
        Matcher matcher = Constants.sandboxEnumeratedTokenPattern.matcher(sandboxToken);
        if (matcher.find()) {
            return new SandboxValue(sandboxToken);
        } else {
            this.warn("The sandbox directive should contain only allow-forms, allow-modals, "
                + "allow-pointer-lock, allow-popups, allow-popups-to-escape-sandbox, "
                + "allow-same-origin, allow-scripts, or allow-top-navigation");
            matcher = Constants.sandboxTokenPattern.matcher(sandboxToken);
            if (matcher.find()) {
                return new SandboxValue(sandboxToken);
            }
        }

        throw this.createError("Expecting sandbox-token but found " + sandboxToken);
    }

    @Nonnull private Set<URI> parseUriList() throws DirectiveParseException {
        Set<URI> uriList = new LinkedHashSet<>();
        if (this.hasNext(DirectiveValueToken.class)) {
            boolean parseException = false;
            String dv = trimRHSWS(this.advance().value);
            for (String v : WSP.split(dv)) {
                try {
                    uriList.add(this.parseUri(v));
                } catch (DirectiveValueParseException e) {
                    parseException = true;
                    this.error(e.getMessage());
                }
            }
            if (parseException) {
                throw INVALID_URI_REFERENCE_LIST;
            }
        }
        if (uriList.isEmpty()) {
            this.error("The report-uri directive must contain at least one uri-reference");
            throw INVALID_URI_REFERENCE_LIST;
        }
        return uriList;
    }

    @Nonnull private URI parseUri(@Nonnull String uri) throws DirectiveValueParseException {
        try {
            return URI.parseWithOrigin(this.origin, uri);
        } catch (IllegalArgumentException ignored) {
            throw this.createError("Expecting uri-reference but found " + uri);
        }
    }

    private class SubDirectiveValueToken extends Token {
        protected SubDirectiveValueToken(@Nonnull String value) {
            super(value);
        }

        @Nonnull @Override public String toJSON() {
            return super.toJSON("SubDirectiveValue");
        }
    }

    private static class DirectiveParseException extends Exception {
        @Nullable Location startLocation;
        @Nullable Location endLocation;

        private DirectiveParseException(@Nonnull String message) {
            super(message);
        }

        @Nonnull @Override public String getMessage() {
            if (startLocation == null) {
                return super.getMessage();
            }
            return startLocation.show() + ": " + super.getMessage();
        }
    }

    protected static class DirectiveValueParseException extends Exception {
        @Nullable Location startLocation;
        @Nullable Location endLocation;

        private DirectiveValueParseException(@Nonnull String message) {
            super(message);
        }

        @Nonnull @Override public String getMessage() {
            if (startLocation == null) {
                return super.getMessage();
            }
            return startLocation.show() + ": " + super.getMessage();
        }
    }
}
