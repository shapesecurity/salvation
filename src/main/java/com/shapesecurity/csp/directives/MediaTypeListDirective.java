package com.shapesecurity.csp.directives;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;
import java.util.stream.Stream;

public abstract class MediaTypeListDirective extends Directive {

    @Nonnull
    // @Nonempty
    private List<MediaType> mediaTypes;

    MediaTypeListDirective(@Nonnull String name, @Nonnull List<MediaType> mediaTypes) {
        super(name);
        this.mediaTypes = mediaTypes;
    }

    @Nonnull
    @Override
    Stream<MediaType> values() {
        return this.mediaTypes.stream();
    }

    @Override
    public void merge(@Nonnull Directive other) {
        if (!(other instanceof MediaTypeListDirective)) {
            throw new Error("MediaTypeListDirective can only be merged with other MediaTypeListDirectives");
        }
        this.mediaTypes = Directive.merge(this.mediaTypes, ((MediaTypeListDirective) other).mediaTypes);
    }

    public boolean matches(@Nonnull MediaType mediaType) {
        return this.mediaTypes.stream().anyMatch((m) -> m.equals(mediaType));
    }

    @Override
    public boolean equals(@Nullable Object other) {
        if (other == null || !(other instanceof MediaTypeListDirective)) return false;
        return this.equalsHelper((MediaTypeListDirective) other);
    }

    @Override
    public int hashCode() {
        return this.hashCodeHelper(0x088E88D3);
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
