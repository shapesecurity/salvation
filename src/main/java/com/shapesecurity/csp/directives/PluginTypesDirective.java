package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.directiveValues.MediaType;

import javax.annotation.Nonnull;
import java.util.List;

public class PluginTypesDirective extends MediaTypeListDirective {
    @Nonnull
    private static final String name = "plugin-types";

    public PluginTypesDirective(@Nonnull List<MediaType> mediaTypes) {
        super(PluginTypesDirective.name, mediaTypes);
    }

}
