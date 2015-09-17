package com.shapesecurity.csp.directiveValues;


import com.shapesecurity.csp.data.GUID;
import com.shapesecurity.csp.data.Origin;
import com.shapesecurity.csp.data.URI;
import com.shapesecurity.csp.interfaces.MatchesSource;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class SchemeSource implements SourceExpression, AncestorSource, MatchesSource {
    @Nonnull private final String value;

    public SchemeSource(@Nonnull String value) {
        this.value = value;
    }

    @Override public boolean matchesSource(@Nonnull Origin origin, @Nonnull URI source) {
        return this.value.matches(source.scheme);
    }

    @Override
    public boolean matchesSource(@Nonnull Origin origin, @Nonnull GUID source) {
        return source.value.startsWith(this.value + ":");
    }

    @Override public boolean equals(@Nullable Object other) {
        if (other == null || !(other instanceof SchemeSource))
            return false;
        return this.value.equals(((SchemeSource) other).value);
    }

    @Override public int hashCode() {
        return this.value.hashCode();
    }

    @Nonnull @Override public String show() {
        return this.value + ":";
    }
}
