package com.shapesecurity.salvation.data;

import javax.annotation.Nonnull;

public class GUID extends Origin {
    @Nonnull public String value;

    public GUID(@Nonnull String value) {
        this.value = value;
    }

    @Override public boolean equals(Object other) {
        if (!(other instanceof GUID))
            return false;
        return ((GUID) other).value.equalsIgnoreCase(this.value);
    }

    @Override public int hashCode() {
        return this.value.toLowerCase().hashCode();
    }

    @Nonnull @Override public String show() {
        return this.value;
    }
}
