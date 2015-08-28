package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.directiveValues.AncestorSource;

import javax.annotation.Nonnull;
import java.util.Set;

public class FrameAncestorsDirective extends AncestorSourceListDirective {
    @Nonnull
    private static final String name = "frame-ancestors";

    public FrameAncestorsDirective(@Nonnull Set<AncestorSource> ancestorSources) {
        super(FrameAncestorsDirective.name, ancestorSources);
    }
}