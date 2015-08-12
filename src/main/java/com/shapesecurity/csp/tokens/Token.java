package com.shapesecurity.csp.tokens;


import com.shapesecurity.csp.data.Location;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public abstract class Token {

    @Nullable
    public Location endLocation;
    @Nullable
    public Location startLocation;

    @Nonnull
    public final String value;

    protected Token(@Nonnull String value) {
        this.value = value;
    }

    @Nonnull
    protected String toJSON(@Nonnull String type) {
        return "{ \"type\": \"" + type + "\", \"value\": \"" + this.value.replace("\\", "\\\\").replace("\"", "\\\"") + "\" }";
    }

    @Nonnull
    public abstract String toJSON();
}

