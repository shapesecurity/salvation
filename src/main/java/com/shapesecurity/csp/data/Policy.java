package com.shapesecurity.csp.data;

import com.shapesecurity.csp.directiveValues.*;
import com.shapesecurity.csp.directiveValues.HashSource.HashAlgorithm;
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

    public void union(@Nonnull Policy other) {
        if (this.directives.containsKey(ReportUriDirective.class) || other.directives.containsKey(ReportUriDirective.class)) {
            throw new IllegalArgumentException("Cannot union policies if either policy contains a report-uri directive.");
        }
        if (!other.origin.equals(this.origin)) {
            other.resolveSelf();
        }
        DefaultSrcDirective defaults = this.getDirectiveByType(DefaultSrcDirective.class);
        if (defaults != null) {
            this.expandDefaultSrc(defaults, this);
        }
        DefaultSrcDirective otherDefaults = other.getDirectiveByType(DefaultSrcDirective.class);
        if (otherDefaults != null) {
            this.expandDefaultSrc(otherDefaults, other);
        }
        other.getDirectives().forEach(this::unionDirective);
        this.optimise();
        other.optimise();
    }

    private void resolveSelf() {
        for (Map.Entry<Class<?>, Directive<? extends DirectiveValue>> entry : this.directives.entrySet()) {
            Directive<? extends DirectiveValue> directive = entry.getValue();
            if (directive instanceof SourceListDirective) {
                SourceListDirective sourceListDirective = (SourceListDirective) directive;
                this.directives.put(entry.getKey(), sourceListDirective.bind(dv ->
                    dv == KeywordSource.Self
                        ? Collections.singleton(new HostSource(this.origin.scheme, this.origin.host, this.origin.port, null))
                        : null
                ));
            }
        }
    }

    private void expandDefaultSrc(@Nonnull DefaultSrcDirective defaultSrcDirective, @Nonnull Policy basePolicy) {
        Set<SourceExpression> defaultSources = defaultSrcDirective.values().collect(Collectors.toCollection(LinkedHashSet::new));
        if (!basePolicy.directives.containsKey(ScriptSrcDirective.class)) {
            this.unionDirective(new ScriptSrcDirective(defaultSources));
        }
        if (!basePolicy.directives.containsKey(StyleSrcDirective.class)) {
            this.unionDirective(new StyleSrcDirective(defaultSources));
        }
        if (!basePolicy.directives.containsKey(ImgSrcDirective.class)) {
            this.unionDirective(new ImgSrcDirective(defaultSources));
        }
        if (!basePolicy.directives.containsKey(ChildSrcDirective.class)) {
            this.unionDirective(new ChildSrcDirective(defaultSources));
        }
        if (!basePolicy.directives.containsKey(ConnectSrcDirective.class)) {
            this.unionDirective(new ConnectSrcDirective(defaultSources));
        }
        if (!basePolicy.directives.containsKey(FontSrcDirective.class)) {
            this.unionDirective(new FontSrcDirective(defaultSources));
        }
        if (!basePolicy.directives.containsKey(MediaSrcDirective.class)) {
            this.unionDirective(new MediaSrcDirective(defaultSources));
        }
        if (!basePolicy.directives.containsKey(ObjectSrcDirective.class)) {
            this.unionDirective(new ObjectSrcDirective(defaultSources));
        }
    }

    private void optimise() {
        DefaultSrcDirective defaultSrcDirective = this.getDirectiveByType(DefaultSrcDirective.class);
        if (defaultSrcDirective == null) return;
        Set<SourceExpression> defaultSources = defaultSrcDirective.values().collect(Collectors.toCollection(LinkedHashSet::new));

        // * remove source directives that are equivalent to default-src
        ScriptSrcDirective scriptSrcDirective = this.getDirectiveByType(ScriptSrcDirective.class);
        if (scriptSrcDirective != null && defaultSources.equals(scriptSrcDirective.values().collect(Collectors.toCollection(LinkedHashSet::new)))) {
            this.directives.remove(ScriptSrcDirective.class);
        }
        StyleSrcDirective styleSrcDirective = this.getDirectiveByType(StyleSrcDirective.class);
        if (styleSrcDirective != null && defaultSources.equals(styleSrcDirective.values().collect(Collectors.toCollection(LinkedHashSet::new)))) {
            this.directives.remove(StyleSrcDirective.class);
        }
        ImgSrcDirective imgSrcDirective = this.getDirectiveByType(ImgSrcDirective.class);
        if (imgSrcDirective != null && defaultSources.equals(imgSrcDirective.values().collect(Collectors.toCollection(LinkedHashSet::new)))) {
            this.directives.remove(ImgSrcDirective.class);
        }
        ChildSrcDirective childSrcDirective = this.getDirectiveByType(ChildSrcDirective.class);
        if (childSrcDirective != null && defaultSources.equals(childSrcDirective.values().collect(Collectors.toCollection(LinkedHashSet::new)))) {
            this.directives.remove(ChildSrcDirective.class);
        }
        ConnectSrcDirective connectSrcDirective = this.getDirectiveByType(ConnectSrcDirective.class);
        if (connectSrcDirective != null && defaultSources.equals(connectSrcDirective.values().collect(Collectors.toCollection(LinkedHashSet::new)))) {
            this.directives.remove(ConnectSrcDirective.class);
        }
        FontSrcDirective fontSrcDirective = this.getDirectiveByType(FontSrcDirective.class);
        if (fontSrcDirective != null && defaultSources.equals(fontSrcDirective.values().collect(Collectors.toCollection(LinkedHashSet::new)))) {
            this.directives.remove(FontSrcDirective.class);
        }
        MediaSrcDirective mediaSrcDirective = this.getDirectiveByType(MediaSrcDirective.class);
        if (mediaSrcDirective != null && defaultSources.equals(mediaSrcDirective.values().collect(Collectors.toCollection(LinkedHashSet::new)))) {
            this.directives.remove(MediaSrcDirective.class);
        }
        ObjectSrcDirective objectSrcDirective = this.getDirectiveByType(ObjectSrcDirective.class);
        if (objectSrcDirective != null && defaultSources.equals (objectSrcDirective.values().collect(Collectors.toCollection(LinkedHashSet::new)))) {
            this.directives.remove(ObjectSrcDirective.class);
        }

        // * remove default-src nonces if the policy contains both script-src and style-src directives
        if (
            this.directives.containsKey(ScriptSrcDirective.class) &&
            this.directives.containsKey(StyleSrcDirective.class)
        ) {
            defaultSources = defaultSrcDirective.values().filter(x -> !(x instanceof NonceSource)).collect(Collectors.toCollection(LinkedHashSet::new));
            defaultSrcDirective = new DefaultSrcDirective(defaultSources);
            this.directives.put(DefaultSrcDirective.class, defaultSrcDirective);
        }

        // * remove unnecessary default-src directives if all source directives exist
        if (
            this.directives.containsKey(ScriptSrcDirective.class) &&
            this.directives.containsKey(StyleSrcDirective.class) &&
            this.directives.containsKey(ImgSrcDirective.class) &&
            this.directives.containsKey(ChildSrcDirective.class) &&
            this.directives.containsKey(ConnectSrcDirective.class) &&
            this.directives.containsKey(FontSrcDirective.class) &&
            this.directives.containsKey(MediaSrcDirective.class) &&
            this.directives.containsKey(ObjectSrcDirective.class)
        ) {
            this.directives.remove(DefaultSrcDirective.class);
        }

        // * remove default-src directives with no source expressions
        if (defaultSources.isEmpty()) {
            this.directives.remove(DefaultSrcDirective.class);
        }

        // * replace host-sources that are equivalent to origin with 'self' keyword-source
        for (Map.Entry<Class<?>, Directive<? extends DirectiveValue>> entry : this.directives.entrySet()) {
            Directive<? extends DirectiveValue> directive = entry.getValue();
            if (directive instanceof SourceListDirective) {
                SourceListDirective sourceListDirective = (SourceListDirective) directive;
                this.directives.put(entry.getKey(), sourceListDirective.bind(dv ->
                    dv instanceof HostSource && ((HostSource) dv).matchesOnlyOrigin(this.origin)
                        ? Collections.singleton(KeywordSource.Self)
                        : null
                ));
            }
        }
    }

    // union a directive if it does not exist; used for policy manipulation and composition
    @SuppressWarnings("unchecked")
    private <V extends DirectiveValue, T extends Directive<V>> void unionDirective(@Nonnull T directive) {
        T oldDirective = (T) this.directives.get(directive.getClass());
        if (oldDirective != null) {
            oldDirective.union(directive);
        } else {
            this.directives.put(directive.getClass(), directive);
        }
    }

    // only add a directive if it doesn't exist; used for handling duplicate directives in CSP headers
    public <V extends DirectiveValue, T extends Directive<V>> void addDirective(@Nonnull T d) {
        Directive<? extends DirectiveValue> directive = this.directives.get(d.getClass());
        if (directive == null) {
            this.directives.put(d.getClass(), d);
            this.optimise();
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
