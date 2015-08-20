package com.shapesecurity.csp.data;

import com.shapesecurity.csp.interfaces.Show;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class Warning implements Show {

    @Nullable
    public Location startLocation;
    @Nullable
    public Location endLocation;

    @Nonnull
    public final String message;

    public Warning(@Nonnull String message) {
        this.message = message;
    }

    @Override
    public String toString() {
        return "Warning: " + message;
    }

    @Nonnull
    @Override
    public String show() {
        if (startLocation == null) {
            return message;
        }
        return startLocation.show() + ": " + message;
    }
}

