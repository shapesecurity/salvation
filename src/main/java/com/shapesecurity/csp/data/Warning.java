package com.shapesecurity.csp.data;

import javax.annotation.Nonnull;

public class Warning {

    @Nonnull
    public final String message;

    public Warning(@Nonnull String message) {
        this.message = message;
    }

    @Override
    public String toString() {
        return "Warning: " + message;
    }
}

