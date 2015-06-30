package com.shapesecurity.csp.directiveValues;

import com.shapesecurity.csp.directives.DirectiveValue;

import javax.annotation.Nonnull;

public class SandboxValue implements DirectiveValue {
    @Nonnull
    private final String value;

    public SandboxValue(@Nonnull String value) {
        this.value = value;
    }

    @Nonnull
    @Override
    public String show() {
        return this.value;
    }

    @Override
    public int hashCode() {
        return this.value.hashCode();
    }

    @Override
    public boolean equals(@Nonnull Object obj) {
        return obj instanceof SandboxValue && ((SandboxValue) obj).value.equals(this.value);
    }
}
