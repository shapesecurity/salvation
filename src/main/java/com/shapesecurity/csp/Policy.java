package com.shapesecurity.csp;

import com.shapesecurity.csp.directives.*;
import com.shapesecurity.csp.sources.HashSource;
import com.shapesecurity.csp.sources.HashSource.HashAlgorithm;
import com.shapesecurity.csp.sources.KeywordSource;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

public class Policy implements Show {

    @Nonnull
    private final Map<Class<?>, Directive<? extends DirectiveValue>> directives;

    @Nonnull
    public String getOrigin() {
        return origin;
    }

    public void setOrigin(@Nonnull String origin) {
        this.origin = origin;
    }

    @Nonnull
    private String origin;

    public Policy(@Nonnull String origin) {
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


    private boolean defaultsAllowHash(HashAlgorithm algorithm, Base64Value hashValue) {
        DefaultSrcDirective defaultSrcDirective = this.getDirectiveByType(DefaultSrcDirective.class);
        if (defaultSrcDirective == null) {
            return true;
        }
        return defaultSrcDirective.matchesHash(algorithm, hashValue);
    }

    private boolean defaultsAllowSource(@Nonnull String s) {
        DefaultSrcDirective defaultSrcDirective = this.getDirectiveByType(DefaultSrcDirective.class);
        if (defaultSrcDirective == null) {
            return true;
        }
        return defaultSrcDirective.matchesUrl(this.origin, s);
    }

    private boolean defaultsAllowUnsafeInline() {
        DefaultSrcDirective defaultSrcDirective = this.getDirectiveByType(DefaultSrcDirective.class);
        if (defaultSrcDirective == null) {
            return true;
        }
        return defaultSrcDirective.values().anyMatch(x -> x == KeywordSource.UnsafeInline);
    }


    public boolean allowsImageFromSource(@Nonnull String url) {
        ImgSrcDirective imgSrcDirective = this.getDirectiveByType(ImgSrcDirective.class);
        if (imgSrcDirective == null) {
            return this.defaultsAllowSource(url);
        }
        return imgSrcDirective.matchesUrl(this.origin, url);
    }

    public boolean allowsImageWithHash(@Nonnull HashAlgorithm algorithm, @Nonnull Base64Value hashValue) {
        ImgSrcDirective imgSrcDirective = this.getDirectiveByType(ImgSrcDirective.class);
        if (imgSrcDirective == null) {
            return this.defaultsAllowHash(algorithm, hashValue);
        }
        return imgSrcDirective.matchesHash(algorithm, hashValue);
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
}
