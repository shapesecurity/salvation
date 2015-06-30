package com.shapesecurity.csp;

import com.shapesecurity.csp.Tokeniser.TokeniserException;
import com.shapesecurity.csp.data.Base64Value;
import com.shapesecurity.csp.data.Origin;
import com.shapesecurity.csp.data.Policy;
import com.shapesecurity.csp.data.URI;
import com.shapesecurity.csp.directiveValues.*;
import com.shapesecurity.csp.directives.*;
import com.shapesecurity.csp.tokens.DirectiveNameToken;
import com.shapesecurity.csp.tokens.DirectiveValueToken;
import com.shapesecurity.csp.tokens.Token;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;

public class Parser {

    @Nonnull
    private final Origin origin;

    @Nonnull
    public static Policy parse(@Nonnull String sourceText, @Nonnull Origin origin) throws ParseException, TokeniserException {
        return new Parser(Tokeniser.tokenise(sourceText), origin).parsePrivate();
    }

    @Nonnull
    public static Policy parse(@Nonnull String sourceText, @Nonnull String origin) throws ParseException, TokeniserException {
        return new Parser(Tokeniser.tokenise(sourceText), URI.parse(origin)).parsePrivate();
    }

    @Nonnull
    private final Token[] tokens;
    private int index = 0;

    private Parser(@Nonnull Token[] tokens, @Nonnull Origin origin) {
        this.origin = origin;
        this.tokens = tokens;
    }


    @Nonnull
    private Token advance() {
        return this.tokens[this.index++];
    }

    private boolean hasNext() {
        return this.index < this.tokens.length;
    }

    private boolean hasNext(@Nonnull String value) {
        return this.hasNext() && value.equals(this.tokens[this.index].value);
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
    private Policy parsePrivate() throws ParseException {
        Policy policy = new Policy(this.origin);
        while (this.hasNext()) {
            if (this.eat(";")) continue;
            policy.addDirective(this.parseDirective());
            if (!this.eat(";")) {
                if (this.hasNext()) {
                    throw this.createError("expecting semicolon or end of policy but found " + this.advance().value);
                } else {
                    break;
                }
            }
        }
        return policy;
    }

    @Nonnull
    private Directive<?> parseDirective() throws ParseException {
        Token token = this.advance();
        if (token instanceof DirectiveNameToken) {
            switch (((DirectiveNameToken) token).subtype) {
                case BaseUri: return new BaseUriDirective(this.parseSourceList());
                case ChildSrc: return new ChildSrcDirective(this.parseSourceList());
                case ConnectSrc: return new ConnectSrcDirective(this.parseSourceList());
                case DefaultSrc: return new DefaultSrcDirective(this.parseSourceList());
                case FontSrc: return new FontSrcDirective(this.parseSourceList());
                case FormAction: return new FormActionDirective(this.parseSourceList());
                case FrameAncestors: return new FrameAncestorsDirective(this.parseAncestorSourceList());
                case FrameSrc: return new FrameSrcDirective(this.parseSourceList());
                case ImgSrc: return new ImgSrcDirective(this.parseSourceList());
                case MediaSrc: return new MediaSrcDirective(this.parseSourceList());
                case ObjectSrc: return new ObjectSrcDirective(this.parseSourceList());
                case PluginTypes: return new PluginTypesDirective(this.parseMediaTypeList());
                case ReportUri: return new ReportUriDirective(this.parseUriList());
                case Sandbox: return new SandboxDirective(this.parseSandboxTokenList());
                case ScriptSrc: return new ScriptSrcDirective(this.parseSourceList());
                case StyleSrc: return new StyleSrcDirective(this.parseSourceList());
            }
        }
        throw this.createError("expecting directive-name but found " + token.value);
    }

    @Nonnull
    private List<MediaType> parseMediaTypeList() throws ParseException {
        ArrayList<MediaType> mediaTypes = new ArrayList<>();
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
    private MediaType parseMediaType() throws ParseException {
        Token token = this.advance();
        Matcher matcher = Constants.mediaTypePattern.matcher(token.value);
        if (matcher.find()) {
            return new MediaType(matcher.group("type"), matcher.group("subtype"));
        }
        throw this.createError("expecting media-type but found " + token.value);
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
        Token token = this.advance();
        if (token instanceof DirectiveValueToken) {
            switch (token.value) {
                case "'self'":
                    return KeywordSource.Self;
                case "'unsafe-inline'":
                    return KeywordSource.UnsafeInline;
                case "'unsafe-eval'":
                    return KeywordSource.UnsafeEval;
                case "'unsafe-redirect'":
                    return KeywordSource.UnsafeRedirect;
                default:
                    if (token.value.startsWith("'nonce-")) {
                        Base64Value b;
                        try {
                            b = new Base64Value(token.value.substring(7, token.value.length() - 1));
                        } catch (Base64Value.IllegalArgumentException | StringIndexOutOfBoundsException e) {
                            throw this.createError(e.getMessage());
                        }
                        return new NonceSource(b);
                    } else if (token.value.startsWith("'sha")) {
                        HashSource.HashAlgorithm algo;
                        switch (token.value.substring(4, 7)) {
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
                                throw this.createError("unrecognised hash algorithm " + token.value.substring(1, 7));
                        }
                        Base64Value b;
                        try {
                            b = new Base64Value(token.value.substring(8, token.value.length() - 1));
                        } catch (Base64Value.IllegalArgumentException e) {
                            throw this.createError(e.getMessage());
                        }
                        return new HashSource(algo, b);
                    } else if (token.value.matches("^" + Constants.schemePart + ":$")) {
                        return new SchemeSource(token.value.substring(0, token.value.length() - 1));
                    } else {
                        Matcher matcher = Constants.hostSourcePattern.matcher(token.value);
                        if (matcher.find()) {
                            String scheme = matcher.group("scheme");
                            if (scheme != null) scheme = scheme.substring(0, scheme.length() - 3);
                            String port = matcher.group("port");
                            port = port == null ? "" : port.substring(1, port.length());
                            String host = matcher.group("host");
                            String path = matcher.group("path");
                            return new HostSource(scheme, host, port, path);
                        }
                    }
            }
        }
        throw this.createError("expecting source-expression but found " + token.value);
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
        Token token = this.advance();
        if (token.value.matches("^" + Constants.schemePart + ":$")) {
            return new SchemeSource(token.value.substring(0, token.value.length() - 1));
        } else {
            Matcher matcher = Constants.hostSourcePattern.matcher(token.value);
            if (matcher.find()) {
                String scheme = matcher.group("scheme");
                if (scheme != null) scheme = scheme.substring(0, scheme.length() - 3);
                String port = matcher.group("port");
                port = port == null ? "" : port.substring(1, port.length());
                String host = matcher.group("host");
                String path = matcher.group("path");
                return new HostSource(scheme, host, port, path);
            }
        }
        throw this.createError("expecting ancestor-source but found " + token.value);
    }

    @Nonnull
    private List<SandboxValue> parseSandboxTokenList() throws ParseException {
        ArrayList<SandboxValue> sandboxTokens = new ArrayList<>();
        while (this.hasNext() && !this.hasNext(";")) {
            sandboxTokens.add(this.parseSandboxToken());
        }
        return sandboxTokens;
    }

    @Nonnull
    private SandboxValue parseSandboxToken() throws ParseException {
        Token token = this.advance();
        Matcher matcher = Constants.sandboxTokenPattern.matcher(token.value);
        if (matcher.find()) {
            return new SandboxValue(token.value);
        }
        throw this.createError("expecting sandbox-token but found " + token.value);
    }

    @Nonnull
    private List<URI> parseUriList() throws ParseException {
        ArrayList<URI> uriList = new ArrayList<>();
        while (this.hasNext() && !this.hasNext(";")) {
            uriList.add(this.parseUri());
        }
        if (uriList.isEmpty()) {
            throw this.createError("report-uri must contain at least one uri-reference");
        }
        return uriList;
    }

    @Nonnull
    private URI parseUri() throws ParseException {
        Token token = this.advance();
        try {
            return URI.parseWithOrigin(this.origin, token.value);
        } catch (IllegalArgumentException ignored) {}
        throw this.createError("expecting uri-reference but found " + token.value);
    }

    public static class ParseException extends Exception {
        private ParseException(@Nonnull String message) {
            super(message);
        }
    }
}
