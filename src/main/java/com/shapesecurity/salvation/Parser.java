package com.shapesecurity.salvation;

import com.shapesecurity.salvation.Tokeniser.TokeniserException;
import com.shapesecurity.salvation.data.*;
import com.shapesecurity.salvation.directiveValues.*;
import com.shapesecurity.salvation.directives.*;
import com.shapesecurity.salvation.tokens.*;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.*;
import java.util.regex.Matcher;

public class Parser {

    @Nonnull protected final Token[] tokens;
    @Nonnull private final Origin origin;
    protected int index = 0;
    @Nullable protected Collection<Warning> warningsOut;

    protected Parser(@Nonnull Token[] tokens, @Nonnull Origin origin,
        @Nullable Collection<Warning> warningsOut) {
        this.origin = origin;
        this.tokens = tokens;
        this.warningsOut = warningsOut;
    }

    @Nonnull public static Policy parse(@Nonnull String sourceText, @Nonnull Origin origin)
        throws ParseException, TokeniserException {
        return new Parser(Tokeniser.tokenise(sourceText), origin, null).parsePolicyAndAssertEOF();
    }

    @Nonnull public static Policy parse(@Nonnull String sourceText, @Nonnull String origin)
        throws ParseException, TokeniserException {
        return new Parser(Tokeniser.tokenise(sourceText), URI.parse(origin), null)
            .parsePolicyAndAssertEOF();
    }

    @Nonnull public static Policy parse(@Nonnull String sourceText, @Nonnull Origin origin,
        @Nonnull Collection<Warning> warningsOut) throws ParseException, TokeniserException {
        return new Parser(Tokeniser.tokenise(sourceText), origin, warningsOut)
            .parsePolicyAndAssertEOF();
    }

    @Nonnull public static Policy parse(@Nonnull String sourceText, @Nonnull String origin,
        @Nonnull Collection<Warning> warningsOut) throws ParseException, TokeniserException {
        return new Parser(Tokeniser.tokenise(sourceText), URI.parse(origin), warningsOut)
            .parsePolicyAndAssertEOF();
    }

    @Nonnull
    public static List<Policy> parseMulti(@Nonnull String sourceText, @Nonnull Origin origin)
        throws ParseException, TokeniserException {
        return new Parser(Tokeniser.tokenise(sourceText), origin, null)
            .parsePolicyListAndAssertEOF();
    }

    @Nonnull
    public static List<Policy> parseMulti(@Nonnull String sourceText, @Nonnull String origin)
        throws ParseException, TokeniserException {
        return new Parser(Tokeniser.tokenise(sourceText), URI.parse(origin), null)
            .parsePolicyListAndAssertEOF();
    }

    @Nonnull
    public static List<Policy> parseMulti(@Nonnull String sourceText, @Nonnull Origin origin,
        @Nonnull Collection<Warning> warningsOut) throws ParseException, TokeniserException {
        return new Parser(Tokeniser.tokenise(sourceText), origin, warningsOut)
            .parsePolicyListAndAssertEOF();
    }

    @Nonnull
    public static List<Policy> parseMulti(@Nonnull String sourceText, @Nonnull String origin,
        @Nonnull Collection<Warning> warningsOut) throws ParseException, TokeniserException {
        return new Parser(Tokeniser.tokenise(sourceText), URI.parse(origin), warningsOut)
            .parsePolicyListAndAssertEOF();
    }

    @Nonnull protected Warning createWarning(@Nonnull String message) {
        return new Warning(message);
    }

    private void warn(@Nonnull String message) {
        if (this.warningsOut != null) {
            this.warningsOut.add(this.createWarning(message));
        }
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

    private Token peek() {
        return this.tokens[this.index];
    }

    private boolean eat(@Nonnull Class<? extends Token> c) {
        if (this.hasNext(c)) {
            this.advance();
            return true;
        }
        return false;
    }

    @Nonnull protected ParseException createUnexpectedEOF(@Nonnull String message) {
        return this.createError(message);
    }

    @Nonnull protected ParseException createError(@Nonnull String message) {
        return new ParseException(message);
    }


    @Nonnull protected Policy parsePolicy() throws ParseException {
        Policy policy = new Policy(this.origin);
        while (this.hasNext()) {
            if (this.eat(DirectiveSeparatorToken.class))
                continue;
            policy.addDirective(this.parseDirective());
            if (!this.eat(DirectiveSeparatorToken.class)) {
                break;
            }
        }
        return policy;
    }

    @Nonnull protected Policy parsePolicyAndAssertEOF() throws ParseException {
        Policy policy = this.parsePolicy();
        if (this.hasNext()) {
            throw this.createError("expecting end of policy but found " + this.advance().value);
        }
        return policy;
    }

    @Nonnull protected List<Policy> parsePolicyList() throws ParseException {
        List<Policy> policies = new ArrayList<>();
        policies.add(this.parsePolicy());
        while (this.hasNext(PolicySeparatorToken.class)) {
            while (this.eat(PolicySeparatorToken.class))
                ;
            policies.add(this.parsePolicy());
        }
        return policies;
    }

    @Nonnull protected List<Policy> parsePolicyListAndAssertEOF() throws ParseException {
        List<Policy> policies = this.parsePolicyList();
        if (this.hasNext()) {
            throw this
                .createError("expecting end of policy list but found " + this.advance().value);
        }
        return policies;
    }

    @Nonnull private Directive<?> parseDirective() throws ParseException {
        if (!this.hasNext(DirectiveNameToken.class)) {
            throw this.createError("expecting directive-name but found " + this.advance().value);
        }
        DirectiveNameToken token = (DirectiveNameToken) this.advance();
        switch (token.subtype) {
            case BaseUri:
                return new BaseUriDirective(this.parseSourceList());
            case ChildSrc:
                return new ChildSrcDirective(this.parseSourceList());
            case ConnectSrc:
                return new ConnectSrcDirective(this.parseSourceList());
            case DefaultSrc:
                return new DefaultSrcDirective(this.parseSourceList());
            case FontSrc:
                return new FontSrcDirective(this.parseSourceList());
            case FormAction:
                return new FormActionDirective(this.parseSourceList());
            case FrameAncestors:
                return new FrameAncestorsDirective(this.parseAncestorSourceList());
            case FrameSrc:
                this.warn(
                    "The frame-src directive is deprecated as of CSP version 1.1. Authors who wish to govern nested browsing contexts SHOULD use the child-src directive instead.");
                return new FrameSrcDirective(this.parseSourceList());
            case ImgSrc:
                return new ImgSrcDirective(this.parseSourceList());
            case MediaSrc:
                return new MediaSrcDirective(this.parseSourceList());
            case ObjectSrc:
                return new ObjectSrcDirective(this.parseSourceList());
            case PluginTypes:
                return new PluginTypesDirective(this.parseMediaTypeList());
            case ReportUri:
                return new ReportUriDirective(this.parseUriList());
            case Sandbox:
                return new SandboxDirective(this.parseSandboxTokenList());
            case ScriptSrc:
                return new ScriptSrcDirective(this.parseSourceList());
            case StyleSrc:
                return new StyleSrcDirective(this.parseSourceList());
            case Referrer:
            case UpgradeInsecureRequests:
                throw this.createError(
                    "The " + token.value + " directive is not in the CSP specification yet.");
            case Allow:
                throw this.createError(
                    "The allow directive has been replaced with default-src and is not in the CSP specification.");
            case Options:
                throw this.createError(
                    "The options directive has been replaced with 'unsafe-inline' and 'unsafe-eval' and is not in the CSP specification.");
        }
        throw this.createError("Not reached.");
    }

    @Nonnull private Set<MediaType> parseMediaTypeList() throws ParseException {
        Set<MediaType> mediaTypes = new LinkedHashSet<>();
        if (!this.hasNext(DirectiveValueToken.class)) {
            throw this.createError("media-type-list must contain at least one media-type");
        }
        mediaTypes.add(this.parseMediaType());
        while (this.hasNext(DirectiveValueToken.class)) {
            mediaTypes.add(this.parseMediaType());
        }
        return mediaTypes;
    }

    @Nonnull private MediaType parseMediaType() throws ParseException {
        Token token = this.advance();
        Matcher matcher = Constants.mediaTypePattern.matcher(token.value);
        if (matcher.find()) {
            return new MediaType(matcher.group("type"), matcher.group("subtype"));
        }
        throw this.createError("expecting media-type but found " + token.value);
    }

    @Nonnull private Set<SourceExpression> parseSourceList() throws ParseException {
        Set<SourceExpression> sourceExpressions = new LinkedHashSet<>();
        if (this.hasNext(DirectiveValueToken.class) && this.peek().value
            .equalsIgnoreCase("'none'")) {
            this.advance();
            sourceExpressions.add(None.INSTANCE);
            return sourceExpressions;
        }
        while (this.hasNext(DirectiveValueToken.class)) {
            sourceExpressions.add(this.parseSourceExpression());
        }
        return sourceExpressions;
    }

    @Nonnull private SourceExpression parseSourceExpression() throws ParseException {
        Token token = this.advance();
        if (token instanceof DirectiveValueToken) {
            switch (token.value.toLowerCase()) {
                case "'self'":
                    return KeywordSource.Self;
                case "'unsafe-inline'":
                    return KeywordSource.UnsafeInline;
                case "'unsafe-eval'":
                    return KeywordSource.UnsafeEval;
                case "'unsafe-redirect'":
                    this.warn("'unsafe-redirect' has been removed from CSP as of version 2.0");
                    return KeywordSource.UnsafeRedirect;
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
                                throw this.createError(
                                    "unrecognised hash algorithm " + token.value.substring(1, 7));
                        }
                        String value = token.value.substring(8, token.value.length() - 1);
                        // convert url-safe base64 to RFC4648 base64
                        String safeValue = value.replace('-', '+').replace('_', '/');
                        Base64Value base64Value = new Base64Value(safeValue);
                        // warn if value is not RFC4648
                        if (value.contains("-") || value.contains("_")) {
                            this.warn(
                                "Invalid base64-value (characters are not in the base64-value grammar). Consider using RFC4648 compliant base64 encoding implementation");
                        }
                        HashSource hashSource = new HashSource(algorithm, base64Value);
                        try {
                            hashSource.validationErrors();
                        } catch (IllegalArgumentException e) {
                            throw this.createError(e.getMessage());
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
        }
        throw this.createError("expecting source-expression but found " + token.value);
    }

    @Nonnull private Set<AncestorSource> parseAncestorSourceList() throws ParseException {
        Set<AncestorSource> ancestorSources = new LinkedHashSet<>();
        if (this.hasNext(DirectiveValueToken.class) && this.peek().value
            .equalsIgnoreCase("'none'")) {
            this.advance();
            ancestorSources.add(None.INSTANCE);
            return ancestorSources;
        }
        while (this.hasNext(DirectiveValueToken.class)) {
            ancestorSources.add(this.parseAncestorSource());
        }
        return ancestorSources;
    }

    @Nonnull private AncestorSource parseAncestorSource() throws ParseException {
        Token token = this.advance();
        if (token.value.equals("'self'")) {
            return KeywordSource.Self;
        }
        if (token.value.matches("^" + Constants.schemePart + ":$")) {
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
        throw this.createError("expecting ancestor-source but found " + token.value);
    }

    @Nonnull private Set<SandboxValue> parseSandboxTokenList() throws ParseException {
        Set<SandboxValue> sandboxTokens = new LinkedHashSet<>();
        while (this.hasNext(DirectiveValueToken.class)) {
            sandboxTokens.add(this.parseSandboxToken());
        }
        return sandboxTokens;
    }

    @Nonnull private SandboxValue parseSandboxToken() throws ParseException {
        Token token = this.advance();
        Matcher matcher = Constants.sandboxTokenPattern.matcher(token.value);
        if (matcher.find()) {
            return new SandboxValue(token.value);
        }
        throw this.createError("expecting sandbox-token but found " + token.value);
    }

    @Nonnull private Set<URI> parseUriList() throws ParseException {
        Set<URI> uriList = new LinkedHashSet<>();
        while (this.hasNext(DirectiveValueToken.class)) {
            uriList.add(this.parseUri());
        }
        if (uriList.isEmpty()) {
            if (!this.hasNext()) {
                throw this.createUnexpectedEOF("report-uri must contain at least one uri-reference");
            }
            throw this.createError("report-uri must contain at least one uri-reference");
        }
        return uriList;
    }

    @Nonnull private URI parseUri() throws ParseException {
        Token token = this.advance();
        try {
            return URI.parseWithOrigin(this.origin, token.value);
        } catch (IllegalArgumentException ignored) {
        }
        throw this.createError("expecting uri-reference but found " + token.value);
    }

    public static class ParseException extends Exception {
        @Nullable Location startLocation;
        @Nullable Location endLocation;

        private ParseException(@Nonnull String message) {
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
