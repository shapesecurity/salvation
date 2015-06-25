package com.shapesecurity.csp.directives;

import javax.annotation.Nonnull;
import java.util.List;

public class PluginTypesDirective extends MediaTypeListDirective {
    @Nonnull
    private static final String name = "plugin-types";

    public PluginTypesDirective(@Nonnull List<MediaType> mediaTypes) {
        super(PluginTypesDirective.name, mediaTypes);
    }

    public boolean matches(@Nonnull MediaType mediaType) {
        return this.values().anyMatch(x -> x.equals(mediaType));
    }
}
