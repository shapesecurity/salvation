package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.sources.AncestorSource;

import javax.annotation.Nonnull;
import java.util.List;

abstract class AncestorSourceListDirective extends Directive<AncestorSource> {
    AncestorSourceListDirective(@Nonnull String name, @Nonnull List<AncestorSource> ancestorSources) {
        super(name, ancestorSources);
    }
}
