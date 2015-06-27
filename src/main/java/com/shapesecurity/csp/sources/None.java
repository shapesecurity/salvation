package com.shapesecurity.csp.sources;

import com.shapesecurity.csp.URI;

import javax.annotation.Nonnull;

public class None implements SourceExpression, AncestorSource {
    private None() {
    }

    @Override
    public boolean matchesUri(@Nonnull URI origin, @Nonnull URI uri) {
        return false;
    }

    @Nonnull
    public static final None INSTANCE = new None();

    @Nonnull
    @Override
    public String show() {
        return "'none'";
    }
}
