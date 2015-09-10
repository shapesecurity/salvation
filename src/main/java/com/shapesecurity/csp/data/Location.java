package com.shapesecurity.csp.data;

import com.shapesecurity.csp.interfaces.Show;

import javax.annotation.Nonnull;

public class Location implements Show {

    @Nonnull public final int line;

    @Nonnull public final int column;

    @Nonnull public final int offset;

    public Location(@Nonnull int line, @Nonnull int column, @Nonnull int offset) {
        this.line = line;
        this.column = column;
        this.offset = offset;
    }

    @Nonnull @Override public String show() {
        return (line + "") + ":" + (column + "");
    }
}
