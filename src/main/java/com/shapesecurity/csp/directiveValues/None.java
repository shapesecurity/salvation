package com.shapesecurity.csp.directiveValues;

import com.shapesecurity.csp.data.Origin;
import com.shapesecurity.csp.data.URI;

import javax.annotation.Nonnull;

public class None implements SourceExpression, AncestorSource {
    @Nonnull public static final None INSTANCE = new None();

    private None() {
    }

    @Override public boolean matchesUri(@Nonnull Origin origin, @Nonnull URI uri) {
        return false;
    }

    @Nonnull @Override public String show() {
        return "'none'";
    }
}
