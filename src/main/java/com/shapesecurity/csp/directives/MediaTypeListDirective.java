package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.directiveValues.MediaType;

import javax.annotation.Nonnull;
import java.util.List;

public abstract class MediaTypeListDirective extends Directive<MediaType> {
    MediaTypeListDirective(@Nonnull String name, @Nonnull List<MediaType> values) {
        super(name, values);
    }

    public boolean matches(@Nonnull MediaType mediaType) {
        return this.values().anyMatch(x -> x.equals(mediaType));
    }
}
