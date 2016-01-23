package com.shapesecurity.salvation.directiveValues;


import com.shapesecurity.salvation.data.GUID;
import com.shapesecurity.salvation.data.Origin;
import com.shapesecurity.salvation.data.URI;
import com.shapesecurity.salvation.interfaces.MatchesSource;

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

    @Override public boolean matchesSource(@Nonnull Origin origin, @Nonnull GUID source) {
        return source.value.startsWith(this.value + ":");
    }

    public boolean matchesProtectedScheme() {
        return this.value.equals("data") || this.value.equals("blob") || this.value.equals("filesystem");
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
