package com.shapesecurity.csp.data;

import javax.annotation.Nonnull;

public class Location {

    @Nonnull
    public final int line;

    @Nonnull
    public final int column;

    @Nonnull
    public final int offset;

    public Location(@Nonnull int line, @Nonnull int column, @Nonnull int offset) {
        this.line = line;
        this.column = column;
        this.offset = offset;
    }

    @Override
    public String toString() {
        return line + ":" + column;
    }
}
