package com.shapesecurity.salvation.directiveValues;

import com.shapesecurity.salvation.directives.DirectiveValue;
import com.shapesecurity.salvation.interfaces.MatchesMediaType;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class MediaType implements DirectiveValue, MatchesMediaType {
    @Nonnull public final String type;
    @Nonnull public final String subtype;

    public MediaType(@Nonnull String type, @Nonnull String subtype) {
        this.type = type;
        this.subtype = subtype;
    }

    @Override public boolean equals(@Nullable Object other) {
        if (other == null || !(other instanceof MediaType))
            return false;
        return this.matchesMediaType((MediaType) other);
    }

    public boolean matchesMediaType(@Nonnull MediaType mediaType) {
        return this.type.equalsIgnoreCase(mediaType.type) && this.subtype.equalsIgnoreCase(mediaType.subtype);
    }

    @Override public int hashCode() {
        return (this.type.toLowerCase().hashCode() ^ 0x887E088E) ^ (this.subtype.toLowerCase().hashCode() ^ 0x33E42712);
    }

    @Nonnull @Override public String show() {
        return this.type + "/" + this.subtype;
    }
}
