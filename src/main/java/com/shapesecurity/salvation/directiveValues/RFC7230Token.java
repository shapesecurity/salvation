package com.shapesecurity.salvation.directiveValues;

import com.shapesecurity.salvation.directives.DirectiveValue;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class RFC7230Token implements DirectiveValue {
    @Nonnull private final String value;

    public RFC7230Token(@Nonnull String value) {
        this.value = value;
    }

    @Nonnull @Override public String show() {
        return this.value;
    }

    @Override public int hashCode() {
        return this.value.hashCode();
    }

    @Override public boolean equals(@Nullable Object other) {
        return other instanceof RFC7230Token && ((RFC7230Token) other).value.equals(this.value);
    }
}
