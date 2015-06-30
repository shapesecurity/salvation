package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.directiveValues.MediaType;
import com.shapesecurity.csp.interfaces.MatchesMediaType;

import javax.annotation.Nonnull;
import java.util.List;

public class PluginTypesDirective extends MediaTypeListDirective implements MatchesMediaType {
    @Nonnull
    private static final String name = "plugin-types";

    public PluginTypesDirective(@Nonnull List<MediaType> mediaTypes) {
        super(PluginTypesDirective.name, mediaTypes);
    }

    public boolean matchesMediaType(@Nonnull MediaType mediaType) {
        return this.values()
                .anyMatch(x -> x.matchesMediaType(mediaType));
    }
}
