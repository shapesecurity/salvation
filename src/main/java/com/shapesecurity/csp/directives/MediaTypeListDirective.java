package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.directiveValues.MediaType;
import com.shapesecurity.csp.interfaces.MatchesMediaType;

import javax.annotation.Nonnull;
import java.util.Set;

public abstract class MediaTypeListDirective extends Directive<MediaType> implements MatchesMediaType {
    MediaTypeListDirective(@Nonnull String name, @Nonnull Set<MediaType> values) {
        super(name, values);
    }

    public boolean matchesMediaType(@Nonnull MediaType mediaType) {
        return this.values()
                .anyMatch(x -> x.matchesMediaType(mediaType));
    }
}
