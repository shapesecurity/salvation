package com.shapesecurity.csp.sources;

import javax.annotation.Nonnull;

public class None implements SourceExpression, AncestorSource {
    private None() {
    }

    @Nonnull
    public static final None INSTANCE = new None();

    @Nonnull
    @Override
    public String show() {
        return "'none'";
    }
}
