package com.shapesecurity.csp.directiveValues;


import com.shapesecurity.csp.data.Origin;
import com.shapesecurity.csp.data.URI;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class SchemeSource implements SourceExpression, AncestorSource {
    @Nonnull private final String value;

    public SchemeSource(@Nonnull String value) {
        this.value = value;
    }

    @Override public boolean matchesUri(@Nonnull Origin origin, @Nonnull URI uri) {
        return this.value.matches(uri.scheme);
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
