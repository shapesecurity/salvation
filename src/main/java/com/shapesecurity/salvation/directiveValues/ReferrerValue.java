package com.shapesecurity.salvation.directiveValues;

import com.shapesecurity.salvation.directives.DirectiveValue;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class ReferrerValue implements DirectiveValue {
    @Nonnull private final String value;

    public ReferrerValue(@Nonnull String value) {
        this.value = value;
    }

    @Nonnull @Override public String show() {
        return this.value;
    }

    @Override public int hashCode() {
        return this.value.hashCode();
    }

    @Override public boolean equals(@Nullable Object other) {
        return other instanceof ReferrerValue && ((ReferrerValue) other).value.equals(this.value);
    }
}
