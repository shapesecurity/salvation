package com.shapesecurity.salvation.data;

import com.shapesecurity.salvation.directiveValues.HashSource.HashAlgorithm;
import com.shapesecurity.salvation.directiveValues.*;
import com.shapesecurity.salvation.directives.*;
import com.shapesecurity.salvation.interfaces.Show;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class Policy implements Show {

    private final static Set<SourceExpression> justNone = Collections.singleton(None.INSTANCE);
    @Nonnull private final Map<Class<?>, Directive<? extends DirectiveValue>> directives;
    @Nonnull private Origin origin;

    public Policy(@Nonnull Origin origin) {
        this.directives = new LinkedHashMap<>();
        this.origin = origin;
    }

    @Nonnull public Origin getOrigin() {
        return origin;
    }

    public void setOrigin(@Nonnull Origin origin) {
        this.origin = origin;
    }

    public void intersect(@Nonnull Policy other) {
        this.mergeUsingStrategy(other, this::intersectDirectivePrivate);
    }

    public void union(@Nonnull Policy other) {
        this.mergeUsingStrategy(other, this::unionDirectivePrivate);
    }

    private void mergeUsingStrategy(@Nonnull Policy other,
        Consumer<Directive<? extends DirectiveValue>> strategy) {
        if (this.directives.containsKey(ReportUriDirective.class) || other.directives
            .containsKey(ReportUriDirective.class)) {
            throw new IllegalArgumentException(
                "Cannot merge policies if either policy contains a report-uri directive.");
        }

        this.resolveSelf();
        other.resolveSelf();

        this.expandDefaultSrc();
        other.expandDefaultSrc();

        other.getDirectives().forEach(strategy);

        this.optimise();
    }

    private void resolveSelf() {
        for (Map.Entry<Class<?>, Directive<? extends DirectiveValue>> entry : this.directives.entrySet()) {
            Directive<? extends DirectiveValue> directive = entry.getValue();
            if (directive instanceof SourceListDirective) {
                this.directives.put(
                    entry.getKey(),
                    ((SourceListDirective) directive).resolveSelf(this.origin)
                );
            }
        }
    }

    private void expandDefaultSrc() {
        DefaultSrcDirective defaultSrcDirective =
            this.getDirectiveByType(DefaultSrcDirective.class);
        Set<SourceExpression> defaultSources;
        if (defaultSrcDirective == null) {
            defaultSources = new LinkedHashSet<>();
            defaultSources.add(HostSource.WILDCARD);
            this.directives.put(DefaultSrcDirective.class, new DefaultSrcDirective(defaultSources));
        } else {
            defaultSources =
                defaultSrcDirective.values().collect(Collectors.toCollection(LinkedHashSet::new));
        }

        if (!this.directives.containsKey(ScriptSrcDirective.class)) {
            this.unionDirectivePrivate(new ScriptSrcDirective(defaultSources));
        }
        if (!this.directives.containsKey(StyleSrcDirective.class)) {
            this.unionDirectivePrivate(new StyleSrcDirective(defaultSources));
        }
        if (!this.directives.containsKey(ImgSrcDirective.class)) {
            this.unionDirectivePrivate(new ImgSrcDirective(defaultSources));
        }
        if (!this.directives.containsKey(ChildSrcDirective.class)) {
            this.unionDirectivePrivate(new ChildSrcDirective(defaultSources));
        }
        if (!this.directives.containsKey(ConnectSrcDirective.class)) {
            this.unionDirectivePrivate(new ConnectSrcDirective(defaultSources));
        }
        if (!this.directives.containsKey(FontSrcDirective.class)) {
            this.unionDirectivePrivate(new FontSrcDirective(defaultSources));
        }
        if (!this.directives.containsKey(MediaSrcDirective.class)) {
            this.unionDirectivePrivate(new MediaSrcDirective(defaultSources));
        }
        if (!this.directives.containsKey(ObjectSrcDirective.class)) {
            this.unionDirectivePrivate(new ObjectSrcDirective(defaultSources));
        }
    }

    private <V extends SourceExpression, T extends Directive<V>> void eliminateRedundantSourceExpression(
        @Nonnull Set<SourceExpression> defaultSources, Class<T> type) {
        T directive = this.getDirectiveByType(type);
        if (directive != null) {
            Set<SourceExpression> values =
                directive.values().collect(Collectors.toCollection(LinkedHashSet::new));
            if (defaultSources.equals(values)
                || (defaultSources.isEmpty() || defaultSources.equals(Policy.justNone)) && (
                values.isEmpty() || values.equals(Policy.justNone))) {
                this.directives.remove(type);
            }
        }
    }

    private void optimise() {
        for (Map.Entry<Class<?>, Directive<? extends DirectiveValue>> entry : this.directives
            .entrySet()) {
            Directive<? extends DirectiveValue> directive = entry.getValue();
            if (directive instanceof SourceListDirective) {
                SourceListDirective sourceListDirective = (SourceListDirective) directive;
                Optional<SourceExpression> star = sourceListDirective.values()
                    .filter(x -> x instanceof HostSource && ((HostSource) x).isWildcard())
                    .findAny();
                if (star.isPresent()) {
                    Set<SourceExpression> newSources =
                        sourceListDirective.values()
                            // * remove all other host sources in a source list that contains *
                            .filter(x -> !(x instanceof HostSource))
                            // * remove schemes sources other than data:, blob:, and filesystem: in source list that contains *
                            .filter(x -> !(x instanceof SchemeSource) || ((SchemeSource) x).matchesProtectedScheme())
                            .collect(Collectors.toCollection(LinkedHashSet::new));
                    newSources.add(star.get());
                    this.directives.put(entry.getKey(), sourceListDirective.construct(newSources));
                } else {
                    this.directives.put(entry.getKey(), sourceListDirective.bind(dv -> {
                        // * replace host-sources that are equivalent to origin with 'self' keyword-source
                        if (
                            dv instanceof HostSource &&
                            this.origin instanceof SchemeHostPortTriple &&
                            ((HostSource) dv).matchesOnlyOrigin((SchemeHostPortTriple) this.origin)
                        ) {
                            return Collections.singleton(KeywordSource.Self);
                        }
                        // * replace 'none' with empty
                        if (dv == None.INSTANCE) {
                            return Collections.emptySet();
                        }
                        // no change
                        return null;
                    }));
                }
            }
        }

        DefaultSrcDirective defaultSrcDirective =
            this.getDirectiveByType(DefaultSrcDirective.class);

        Set<SourceExpression> defaultSources;
        if (defaultSrcDirective == null) {
            defaultSources = new LinkedHashSet<>();
            defaultSources.add(HostSource.WILDCARD);
        } else {
            defaultSources =
                defaultSrcDirective.values().collect(Collectors.toCollection(LinkedHashSet::new));
        }

        // * remove source directives that are equivalent to default-src
        this.eliminateRedundantSourceExpression(defaultSources, ScriptSrcDirective.class);
        this.eliminateRedundantSourceExpression(defaultSources, StyleSrcDirective.class);
        this.eliminateRedundantSourceExpression(defaultSources, ImgSrcDirective.class);
        this.eliminateRedundantSourceExpression(defaultSources, ChildSrcDirective.class);
        this.eliminateRedundantSourceExpression(defaultSources, ConnectSrcDirective.class);
        this.eliminateRedundantSourceExpression(defaultSources, FontSrcDirective.class);
        this.eliminateRedundantSourceExpression(defaultSources, MediaSrcDirective.class);
        this.eliminateRedundantSourceExpression(defaultSources, ObjectSrcDirective.class);

        // * remove default-src nonces if the policy contains both script-src and style-src directives
        if (this.directives.containsKey(ScriptSrcDirective.class) && this.directives
            .containsKey(StyleSrcDirective.class)) {
            defaultSources.removeIf(x -> x instanceof NonceSource);
            defaultSrcDirective = new DefaultSrcDirective(defaultSources);
            this.directives.put(DefaultSrcDirective.class, defaultSrcDirective);
        }

        // * remove unnecessary default-src directives if all source directives exist
        if (this.directives.containsKey(ScriptSrcDirective.class) &&
            this.directives.containsKey(StyleSrcDirective.class) &&
            this.directives.containsKey(ImgSrcDirective.class) &&
            this.directives.containsKey(ChildSrcDirective.class) &&
            this.directives.containsKey(ConnectSrcDirective.class) &&
            this.directives.containsKey(FontSrcDirective.class) &&
            this.directives.containsKey(MediaSrcDirective.class) &&
            this.directives.containsKey(ObjectSrcDirective.class)) {
            this.directives.remove(DefaultSrcDirective.class);
        }

        // remove `default-src *`
        if (defaultSources.size() == 1) {
            SourceExpression first = defaultSources.iterator().next();
            if (first instanceof HostSource && ((HostSource) first).isWildcard()) {
                this.directives.remove(DefaultSrcDirective.class);
            }
        }
    }

    public void unionDirective(@Nonnull Directive<? extends DirectiveValue> directive) {
        this.resolveSelf();
        if (directive instanceof SourceListDirective) {
            directive = ((SourceListDirective) directive).resolveSelf(this.origin);
        }
        if(!(directive instanceof DefaultSrcDirective)) {
            this.expandDefaultSrc();
        }
        this.unionDirectivePrivate(directive);
        this.optimise();
    }

    public void intersectDirective(@Nonnull Directive<? extends DirectiveValue> directive) {
        this.resolveSelf();
        if (directive instanceof SourceListDirective) {
            directive = ((SourceListDirective) directive).resolveSelf(this.origin);
        }
        if(!(directive instanceof DefaultSrcDirective)) {
            this.expandDefaultSrc();
        }
        this.intersectDirectivePrivate(directive);
        this.optimise();
    }

    // union a directive if it does not exist; used for policy manipulation and composition
    private <V extends DirectiveValue, T extends Directive<V>> void unionDirectivePrivate(
        @Nonnull T directive) {
        @SuppressWarnings("unchecked") T oldDirective =
            (T) this.directives.get(directive.getClass());
        if (oldDirective != null) {
            oldDirective.union(directive);
        } else {
            this.directives.put(directive.getClass(), directive);
        }
    }

    private <V extends DirectiveValue, T extends Directive<V>> void intersectDirectivePrivate(
        @Nonnull T directive) {
        @SuppressWarnings("unchecked") T oldDirective =
            (T) this.directives.get(directive.getClass());
        if (oldDirective != null) {
            oldDirective.intersect(directive);
        } else {
            this.directives.put(directive.getClass(), directive);
        }
    }

    // only add a directive if it doesn't exist; used for handling duplicate directives in CSP headers
    public <V extends DirectiveValue, T extends Directive<V>> void addDirective(@Nonnull T d) {
        Directive<? extends DirectiveValue> directive = this.directives.get(d.getClass());
        if (directive == null) {
            this.directives.put(d.getClass(), d);
            this.expandDefaultSrc();
            this.resolveSelf();
            this.optimise();
        }
    }

    @Nonnull public Collection<Directive<? extends DirectiveValue>> getDirectives() {
        return this.directives.values();
    }

    @SuppressWarnings("unchecked") @Nullable
    public <V extends DirectiveValue, T extends Directive<V>> T getDirectiveByType(
        @Nonnull Class<T> type) {
        T d = (T) this.directives.get(type);
        if (d == null)
            return null;
        return d;
    }

    @Override public boolean equals(@Nullable Object other) {
        if (other == null || !(other instanceof Policy))
            return false;
        return this.directives.size() == ((Policy) other).directives.size() && this.directives
            .equals(((Policy) other).directives);
    }

    @Override public int hashCode() {
        return this.directives.values().stream().map(Object::hashCode)
            .reduce(0x19E465E0, (a, b) -> a ^ b);
    }

    @Nonnull @Override public String show() {
        StringBuilder sb = new StringBuilder();
        if (this.directives.isEmpty()) {
            return "";
        }
        boolean first = true;
        for (Directive<?> d : this.directives.values()) {
            if (!first)
                sb.append("; ");
            first = false;
            sb.append(d.show());
        }
        return sb.toString();
    }


    private boolean defaultsAllowHash(@Nonnull HashAlgorithm algorithm,
        @Nonnull Base64Value hashValue) {
        if (this.defaultsAllowUnsafeInline())
            return true;
        DefaultSrcDirective defaultSrcDirective =
            this.getDirectiveByType(DefaultSrcDirective.class);
        if (defaultSrcDirective == null) {
            return true;
        }
        return defaultSrcDirective.matchesHash(algorithm, hashValue);
    }

    private boolean defaultsAllowNonce(@Nonnull String nonce) {
        if (this.defaultsAllowUnsafeInline())
            return true;
        DefaultSrcDirective defaultSrcDirective =
            this.getDirectiveByType(DefaultSrcDirective.class);
        if (defaultSrcDirective == null) {
            return true;
        }
        return defaultSrcDirective.matchesNonce(nonce);
    }

    private boolean defaultsAllowNonce(@Nonnull Base64Value nonce) {
        return this.defaultsAllowNonce(nonce.value);
    }


    // 7.4.1
    private boolean defaultsAllowSource(@Nonnull URI source) {
        DefaultSrcDirective defaultSrcDirective =
            this.getDirectiveByType(DefaultSrcDirective.class);
        if (defaultSrcDirective == null) {
            return true;
        }
        return defaultSrcDirective.matchesSource(this.origin, source);
    }

    private boolean defaultsAllowSource(@Nonnull GUID source) {
        DefaultSrcDirective defaultSrcDirective =
            this.getDirectiveByType(DefaultSrcDirective.class);
        if (defaultSrcDirective == null) {
            return false;
        }
        return defaultSrcDirective.matchesSource(this.origin, source);
    }

    private boolean defaultsAllowUnsafeInline() {
        DefaultSrcDirective defaultSrcDirective =
            this.getDirectiveByType(DefaultSrcDirective.class);
        if (defaultSrcDirective == null) {
            return false;
        }
        return defaultSrcDirective.values().anyMatch(x -> x == KeywordSource.UnsafeInline);
    }


    public boolean allowsImgFromSource(@Nonnull URI source) {
        ImgSrcDirective imgSrcDirective = this.getDirectiveByType(ImgSrcDirective.class);
        if (imgSrcDirective == null) {
            return this.defaultsAllowSource(source);
        }
        return imgSrcDirective.matchesSource(this.origin, source);
    }

    public boolean allowsImgFromSource(@Nonnull GUID source) {
        ImgSrcDirective imgSrcDirective = this.getDirectiveByType(ImgSrcDirective.class);
        if (imgSrcDirective == null) {
            return this.defaultsAllowSource(source);
        }
        return imgSrcDirective.matchesSource(this.origin, source);
    }

    public boolean allowsScriptFromSource(@Nonnull URI source) {
        ScriptSrcDirective scriptSrcDirective = this.getDirectiveByType(ScriptSrcDirective.class);
        if (scriptSrcDirective == null) {
            return this.defaultsAllowSource(source);
        }
        return scriptSrcDirective.matchesSource(this.origin, source);
    }

    public boolean allowsScriptFromSource(@Nonnull GUID source) {
        ScriptSrcDirective scriptSrcDirective = this.getDirectiveByType(ScriptSrcDirective.class);
        if (scriptSrcDirective == null) {
            return this.defaultsAllowSource(source);
        }
        return scriptSrcDirective.matchesSource(this.origin, source);
    }

    public boolean allowsStyleFromSource(@Nonnull URI source) {
        StyleSrcDirective styleSrcDirective = this.getDirectiveByType(StyleSrcDirective.class);
        if (styleSrcDirective == null) {
            return this.defaultsAllowSource(source);
        }
        return styleSrcDirective.matchesSource(this.origin, source);
    }

    public boolean allowsStyleFromSource(@Nonnull GUID source) {
        StyleSrcDirective styleSrcDirective = this.getDirectiveByType(StyleSrcDirective.class);
        if (styleSrcDirective == null) {
            return this.defaultsAllowSource(source);
        }
        return styleSrcDirective.matchesSource(this.origin, source);
    }

    public boolean allowsConnectTo(@Nonnull URI source) {
        ConnectSrcDirective connectSrcDirective =
            this.getDirectiveByType(ConnectSrcDirective.class);
        if (connectSrcDirective == null) {
            return this.defaultsAllowSource(source);
        }
        return connectSrcDirective.matchesSource(this.origin, source);
    }

    public boolean allowsConnectTo(@Nonnull GUID source) {
        ConnectSrcDirective connectSrcDirective =
            this.getDirectiveByType(ConnectSrcDirective.class);
        if (connectSrcDirective == null) {
            return this.defaultsAllowSource(source);
        }
        return connectSrcDirective.matchesSource(this.origin, source);
    }

    public boolean allowsStyleWithHash(@Nonnull HashAlgorithm algorithm,
        @Nonnull Base64Value hashValue) {
        if (this.allowsUnsafeInlineStyle())
            return true;
        StyleSrcDirective styleSrcDirective = this.getDirectiveByType(StyleSrcDirective.class);
        if (styleSrcDirective == null) {
            return this.defaultsAllowHash(algorithm, hashValue);
        }
        return styleSrcDirective.matchesHash(algorithm, hashValue);
    }

    public boolean allowsScriptWithHash(@Nonnull HashAlgorithm algorithm,
        @Nonnull Base64Value hashValue) {
        if (this.allowsUnsafeInlineScript())
            return true;
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
        PluginTypesDirective pluginTypesDirective =
            this.getDirectiveByType(PluginTypesDirective.class);
        if (pluginTypesDirective == null) {
            return false;
        }

        return pluginTypesDirective.matchesMediaType(mediaType);
    }

    public boolean allowsScriptWithNonce(@Nonnull String nonce) {
        if (this.allowsUnsafeInlineScript())
            return true;
        ScriptSrcDirective scriptSrcDirective = this.getDirectiveByType(ScriptSrcDirective.class);
        if (scriptSrcDirective == null) {
            return this.defaultsAllowNonce(nonce);
        }
        return scriptSrcDirective.matchesNonce(nonce);
    }

    public boolean allowsScriptWithNonce(@Nonnull Base64Value nonce) {
        return this.allowsScriptWithNonce(nonce.value);
    }

    public boolean allowsStyleWithNonce(@Nonnull String nonce) {
        if (this.allowsUnsafeInlineScript())
            return true;
        StyleSrcDirective styleSrcDirective = this.getDirectiveByType(StyleSrcDirective.class);
        if (styleSrcDirective == null) {
            return this.defaultsAllowNonce(nonce);
        }
        return styleSrcDirective.matchesNonce(nonce);
    }

    public boolean allowsStyleWithNonce(@Nonnull Base64Value nonce) {
        return this.allowsStyleWithNonce(nonce.value);
    }

    public boolean allowsChildFromSource(@Nonnull URI source) {
        ChildSrcDirective childSrcDirective = this.getDirectiveByType(ChildSrcDirective.class);
        if (childSrcDirective == null) {
            return this.defaultsAllowSource(source);
        }
        return childSrcDirective.matchesSource(this.origin, source);
    }

    public boolean allowsFrameFromSource(@Nonnull URI source) {
        FrameSrcDirective frameSrcDirective = this.getDirectiveByType(FrameSrcDirective.class);
        if (frameSrcDirective == null) {
            return this.allowsChildFromSource(source);
        }
        return frameSrcDirective.matchesSource(this.origin, source);
    }
}
