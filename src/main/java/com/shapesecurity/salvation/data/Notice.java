package com.shapesecurity.salvation.data;

import com.shapesecurity.salvation.interfaces.Show;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class Notice implements Show {

    @Nonnull public final Type type;
    @Nonnull public final String message;
    @Nullable public Location startLocation;
    @Nullable public Location endLocation;


    public Notice(@Nonnull Type type, @Nonnull String message) {
        this.message = message;
        this.type = type;
    }

    @Override public String toString() {
        return type.getValue() + ": " + message;
    }

    @Nonnull @Override public String show() {
        if (startLocation == null) {
            return message;
        }
        return startLocation.show() + ": " + message;
    }

    public enum Type {
        INFO("Info"),
        WARNING("Warning"),
        ERROR("Error");

        String value;

        Type(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }
}

