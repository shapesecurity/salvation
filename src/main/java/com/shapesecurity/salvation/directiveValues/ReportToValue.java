package com.shapesecurity.salvation.directiveValues;

import com.shapesecurity.salvation.directives.DirectiveValue;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class ReportToValue implements DirectiveValue {
    @Nonnull private final String value;

    public ReportToValue(@Nonnull String value) {
        this.value = value;
    }

    @Nonnull @Override public String show() {
        return this.value;
    }

    @Override public int hashCode() {
        return this.value.hashCode();
    }

    @Override public boolean equals(@Nullable Object other) {
        return other instanceof ReportToValue && ((ReportToValue) other).value.equals(this.value);
    }
}
