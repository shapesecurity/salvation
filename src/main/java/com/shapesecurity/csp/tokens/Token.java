package com.shapesecurity.csp.tokens;


import javax.annotation.Nonnull;

public abstract class Token {

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

