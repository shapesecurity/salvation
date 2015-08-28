package com.shapesecurity.csp.data;

import com.shapesecurity.csp.directiveValues.HashSource.HashAlgorithm;
import com.shapesecurity.csp.directiveValues.KeywordSource;
import com.shapesecurity.csp.directiveValues.MediaType;
import com.shapesecurity.csp.directiveValues.NonceSource;
import com.shapesecurity.csp.directiveValues.SourceExpression;
import com.shapesecurity.csp.directives.*;
import com.shapesecurity.csp.interfaces.Show;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.*;
import java.util.stream.Collectors;

public class Policy implements Show {

    @Nonnull
    private final Map<Class<?>, Directive<? extends DirectiveValue>> directives;

    @Nonnull
    public Origin getOrigin() {
        return origin;
    }

    public void setOrigin(@Nonnull Origin origin) {
        this.origin = origin;
    }

    @Nonnull
    private Origin origin;

    public Policy(@Nonnull Origin origin) {
        this.directives = new LinkedHashMap<>();
        this.origin = origin;
    }

    public void merge(@Nonnull Policy other) {
        other.getDirectives().forEach(this::mergeDirective);
    }

    // merge a directive if it does not exist; used for policy manipulation and composition
    @SuppressWarnings("unchecked")
    private <V extends DirectiveValue, T extends Directive<V>> void mergeDirective(@Nonnull T directive) {
        T oldDirective = (T) this.directives.get(directive.getClass());
        if (oldDirective != null) {
            oldDirective.merge(directive);
        } else {
            this.directives.put(directive.getClass(), directive);
        }
    }

    // only add a directive if it doesn't exist; used for handling duplicate directives in CSP headers
    public <V extends DirectiveValue, T extends Directive<V>> void addDirective(@Nonnull T d) {
        Directive<? extends DirectiveValue> directive = this.directives.get(d.getClass());
        if (directive == null) {
            this.directives.put(d.getClass(), d);
        }
    }

    @Nonnull
    public Collection<Directive<? extends DirectiveValue>> getDirectives() {
        return this.directives.values();
    }

    @SuppressWarnings("unchecked")
    @Nullable
    public <V extends DirectiveValue, T extends Directive<V>> T getDirectiveByType(@Nonnull Class<T> type) {
        T d = (T) this.directives.get(type);
        if (d == null) return null;
        return d;
    }

    @Override
    public boolean equals(@Nullable Object other) {
        if (other == null || !(other instanceof Policy)) return false;
        return this.directives.size() == ((Policy) other).directives.size() &&
                this.directives.equals(((Policy) other).directives);
    }

    @Override
    public int hashCode() {
        return this.directives.values().stream().map(Object::hashCode).reduce(0x19E465E0, (a, b) -> a ^ b);
    }

    @Nonnull
    @Override
    public String show() {
        StringBuilder sb = new StringBuilder();
        if (this.directives.isEmpty()) {
            return "";
        }
        boolean first = true;
        for (Directive<?> d : this.directives.values()) {
            if (!first) sb.append("; ");
            first = false;
            sb.append(d.show());
        }
        return sb.toString();
    }


    private boolean defaultsAllowHash(@Nonnull HashAlgorithm algorithm, @Nonnull Base64Value hashValue) {
        if(this.defaultsAllowUnsafeInline()) return true;
        DefaultSrcDirective defaultSrcDirective = this.getDirectiveByType(DefaultSrcDirective.class);
        if (defaultSrcDirective == null) {
            return true;
        }
        return defaultSrcDirective.matchesHash(algorithm, hashValue);
    }

    private boolean defaultsAllowNonce(@Nonnull Base64Value nonce) {
        if(this.defaultsAllowUnsafeInline()) return true;
        DefaultSrcDirective defaultSrcDirective = this.getDirectiveByType(DefaultSrcDirective.class);
        if (defaultSrcDirective == null) {
            return true;
        }
        return defaultSrcDirective.matchesNonce(nonce);
    }


    // 7.4.1
    private boolean defaultsAllowSource(@Nonnull URI s) {
        DefaultSrcDirective defaultSrcDirective = this.getDirectiveByType(DefaultSrcDirective.class);
        if (defaultSrcDirective == null) {
            return true;
        }
        return defaultSrcDirective.matchesUri(this.origin, s);
    }

    private boolean defaultsAllowUnsafeInline() {
        DefaultSrcDirective defaultSrcDirective = this.getDirectiveByType(DefaultSrcDirective.class);
        if (defaultSrcDirective == null) {
            return false;
        }
        return defaultSrcDirective.values().anyMatch(x -> x == KeywordSource.UnsafeInline);
    }


    public boolean allowsImgFromSource(@Nonnull URI uri) {
        ImgSrcDirective imgSrcDirective = this.getDirectiveByType(ImgSrcDirective.class);
        if (imgSrcDirective == null) {
            return this.defaultsAllowSource(uri);
        }
        return imgSrcDirective.matchesUri(this.origin, uri);
    }

    public boolean allowsScriptFromSource(@Nonnull URI uri) {
        ScriptSrcDirective scriptSrcDirective = this.getDirectiveByType(ScriptSrcDirective.class);
        if (scriptSrcDirective == null) {
            return this.defaultsAllowSource(uri);
        }
        return scriptSrcDirective.matchesUri(this.origin, uri);
    }

    public boolean allowsStyleFromSource(@Nonnull URI uri) {
        StyleSrcDirective styleSrcDirective = this.getDirectiveByType(StyleSrcDirective.class);
        if (styleSrcDirective == null) {
            return this.defaultsAllowSource(uri);
        }
        return styleSrcDirective.matchesUri(this.origin, uri);
    }

    public boolean allowsStyleWithHash(@Nonnull HashAlgorithm algorithm, @Nonnull Base64Value hashValue) {
        if (this.allowsUnsafeInlineStyle()) return true;
        StyleSrcDirective styleSrcDirective = this.getDirectiveByType(StyleSrcDirective.class);
        if (styleSrcDirective == null) {
            return this.defaultsAllowHash(algorithm, hashValue);
        }
        return styleSrcDirective.matchesHash(algorithm, hashValue);
    }

    public boolean allowsScriptWithHash(@Nonnull HashAlgorithm algorithm, @Nonnull Base64Value hashValue) {
        if (this.allowsUnsafeInlineScript()) return true;
        ScriptSrcDirective scriptSrcDirective = this.getDirectiveByType(ScriptSrcDirective.class);
        if (scriptSrcDirective == null) {
            return this.defaultsAllowHash(algorithm, hashValue);
        }
        return scriptSrcDirective.matchesHash(algorithm, hashValue);
    }

    public boolean allowsUnsafeInlineScript() {
        ScriptSrcDirective scriptSrcDirective = this.getDirectiveByType(ScriptSrcDirective.class);
        if (scriptSrcDirective == null) {
            return this.defaultsAllowUnsafeInline();
        }
        return scriptSrcDirective.values().anyMatch(x -> x == KeywordSource.UnsafeInline);
    }

    public boolean allowsUnsafeInlineStyle() {
        StyleSrcDirective styleSrcDirective = this.getDirectiveByType(StyleSrcDirective.class);
        if (styleSrcDirective == null) {
            return this.defaultsAllowUnsafeInline();
        }
        return styleSrcDirective.values().anyMatch(x -> x == KeywordSource.UnsafeInline);
    }

    public boolean allowsPlugin(@Nonnull MediaType mediaType) {
        PluginTypesDirective pluginTypesDirective = this.getDirectiveByType(PluginTypesDirective.class);
        if (pluginTypesDirective == null) {
            return false;
        }

        return pluginTypesDirective.matchesMediaType(mediaType);
    }

    public boolean allowsScriptWithNonce(@Nonnull Base64Value nonce) {
        if (this.allowsUnsafeInlineScript()) return true;
        ScriptSrcDirective scriptSrcDirective = this.getDirectiveByType(ScriptSrcDirective.class);
        if (scriptSrcDirective == null) {
            return this.defaultsAllowNonce(nonce);
        }
        return scriptSrcDirective.matchesNonce(nonce);
    }

    public boolean allowsStyleWithNonce(@Nonnull Base64Value nonce) {
        if (this.allowsUnsafeInlineScript()) return true;
        StyleSrcDirective styleSrcDirective = this.getDirectiveByType(StyleSrcDirective.class);
        if (styleSrcDirective == null) {
            return this.defaultsAllowNonce(nonce);
        }
        return styleSrcDirective.matchesNonce(nonce);
    }

    public boolean allowsConnectTo(@Nonnull URI uri) {
        ConnectSrcDirective connectSrcDirective = this.getDirectiveByType(ConnectSrcDirective.class);
        if (connectSrcDirective == null) {
            return this.defaultsAllowSource(uri);
        }
        return connectSrcDirective.matchesUri(this.origin, uri);

    }
}
