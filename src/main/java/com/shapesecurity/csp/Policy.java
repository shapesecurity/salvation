package com.shapesecurity.csp;

import com.shapesecurity.csp.directives.*;
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
    public URI getOrigin() {
        return origin;
    }

    public void setOrigin(@Nonnull URI origin) {
        this.origin = origin;
    }

    @Nonnull
    private URI origin;

    public Policy(@Nonnull URI origin) {
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
        DefaultSrcDirective defaultSrcDirective = this.getDirectiveByType(DefaultSrcDirective.class);
        if (defaultSrcDirective == null) {
            return true;
        }
        return defaultSrcDirective.matchesHash(algorithm, hashValue);
    }

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


    public boolean allowsImageFromSource(@Nonnull URI uri) {
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

    public boolean allowsPlugin(@Nonnull MediaTypeListDirective.MediaType mediaType) {
        PluginTypesDirective pluginTypesDirective = this.getDirectiveByType(PluginTypesDirective.class);
        if (pluginTypesDirective == null) {
            return false;
        }

        return pluginTypesDirective.values().anyMatch(x -> x == mediaType);
    }
}
