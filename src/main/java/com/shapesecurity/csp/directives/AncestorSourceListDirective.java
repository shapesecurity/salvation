package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.directiveValues.AncestorSource;

import javax.annotation.Nonnull;
import java.util.Set;

abstract class AncestorSourceListDirective extends Directive<AncestorSource> {
    AncestorSourceListDirective(@Nonnull String name, @Nonnull Set<AncestorSource> ancestorSources) {
        super(name, ancestorSources);
    }
}
