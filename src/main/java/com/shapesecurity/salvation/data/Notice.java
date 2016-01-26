package com.shapesecurity.salvation.data;

import com.shapesecurity.salvation.interfaces.Show;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.stream.Collectors;

public class Notice implements Show {

    @Nonnull public final Type type;
    @Nonnull public final String message;
    @Nullable public Location startLocation;
    @Nullable public Location endLocation;


    public Notice(@Nonnull Type type, @Nonnull String message) {
        this.message = message;
        this.type = type;
    }

    @Nonnull public static ArrayList<Notice> getAllErrors(@Nonnull ArrayList<Notice> notices) {
        if (notices == null) {
            return new ArrayList<>();
        }
        return notices.stream().filter(Notice::isError).collect(Collectors.toCollection(ArrayList::new));
    }

    @Nonnull public static ArrayList<Notice> getAllWarnings(@Nonnull ArrayList<Notice> notices) {
        if (notices == null) {
            return new ArrayList<>();
        }
        return notices.stream().filter(Notice::isWarning).collect(Collectors.toCollection(ArrayList::new));
    }

    @Nonnull public static ArrayList<Notice> getAllInfos(@Nonnull ArrayList<Notice> notices) {
        if (notices == null) {
            return new ArrayList<>();
        }
        return notices.stream().filter(Notice::isInfo).collect(Collectors.toCollection(ArrayList::new));
    }

    @Override public String toString() {
        return type.getValue() + ": " + message;
    }

    public boolean isError() {
        return this.type == Type.ERROR;
    }

    public boolean isWarning() {
        return this.type == Type.WARNING;
    }

    public boolean isInfo() {
        return this.type == Type.INFO;
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

