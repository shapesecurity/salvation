package com.shapesecurity.csp.sources;


import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class SchemeSource implements SourceExpression, AncestorSource {
    @Nonnull
    private final String value;

    public SchemeSource(@Nonnull String value) {
        this.value = value;
    }

    @Nonnull
    private static String getSchemeOf(@Nonnull String url) {
        // TODO: this should be implemented properly by a URL library when we stop using String for URLs
        return url.substring(0, url.indexOf(':'));
    }

    @Override
    public boolean matchesUrl(@Nonnull String origin, @Nonnull String url) {
        return this.value.matches(getSchemeOf(url));
    }

    @Override
    public boolean equals(@Nullable Object other) {
        if (other == null || !(other instanceof SchemeSource)) return false;
        return this.value.equals(((SchemeSource) other).value);
    }

    @Override
    public int hashCode() {
        return this.value.hashCode();
    }

    @Nonnull
    @Override
    public String show() {
        return this.value + ":";
    }
}