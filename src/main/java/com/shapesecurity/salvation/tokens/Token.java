package com.shapesecurity.salvation.tokens;


import com.shapesecurity.salvation.data.Location;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public abstract class Token {

    @Nonnull public final String value;
    @Nullable public Location startLocation;
    @Nullable public Location endLocation;

    protected Token(@Nonnull String value) {
        this.value = value;
    }

    @Nonnull protected String toJSON(@Nonnull String type) {
        return "{ \"type\": \"" + type + "\", \"value\": \"" + this.value.replace("\\", "\\\\")
            .replace("\"", "\\\"") + "\" }";
    }

    @Nonnull public abstract String toJSON();
}

