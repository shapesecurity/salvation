package com.shapesecurity.salvation.directives;

import com.shapesecurity.salvation.directiveValues.AncestorSource;

import javax.annotation.Nonnull;
import java.util.Set;

abstract class AncestorSourceListDirective extends Directive<AncestorSource> {
    AncestorSourceListDirective(@Nonnull String name,
        @Nonnull Set<AncestorSource> ancestorSources) {
        super(name, ancestorSources);
    }
}
