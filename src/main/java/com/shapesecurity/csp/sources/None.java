package com.shapesecurity.csp.sources;

import javax.annotation.Nonnull;

public class None implements SourceExpression, AncestorSource {
    private None() {
    }

    @Override
    public boolean matchesUrl(@Nonnull String origin, @Nonnull String url) {
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
