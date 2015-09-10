package com.shapesecurity.csp.directiveValues;

import com.shapesecurity.csp.directives.DirectiveValue;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class SandboxValue implements DirectiveValue {
    @Nonnull private final String value;

    public SandboxValue(@Nonnull String value) {
        this.value = value;
    }

    @Nonnull @Override public String show() {
        return this.value;
    }

    @Override public int hashCode() {
        return this.value.hashCode();
    }

    @Override public boolean equals(@Nullable Object other) {
        return other instanceof SandboxValue && ((SandboxValue) other).value.equals(this.value);
    }
}
