package com.shapesecurity.csp.directives;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;

public abstract class MediaTypeListDirective extends Directive<MediaTypeListDirective.MediaType> {

    MediaTypeListDirective(@Nonnull String name, @Nonnull List<MediaType> values) {
        super(name, values);
    }

    public static class MediaType implements DirectiveValue {
        @Nonnull
        public final String type;
        @Nonnull
        public final String subtype;

        public MediaType(@Nonnull String type, @Nonnull String subtype) {
            this.type = type;
            this.subtype = subtype;
        }

        @Override
        public boolean equals(@Nullable Object other) {
            if (other == null || !(other instanceof MediaType)) return false;
            return ((MediaType) other).type.equalsIgnoreCase(this.type) &&
                    ((MediaType) other).subtype.equalsIgnoreCase(this.subtype);
        }

        @Override
        public int hashCode() {
            return (this.type.hashCode() ^ 0x887E088E) ^ (this.subtype.hashCode() ^ 0x33E42712);
        }

        @Nonnull
        @Override
        public String show() {
            return this.type + "/" + this.subtype;
        }
    }
}
