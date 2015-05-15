package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.sources.AncestorSource;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;
import java.util.stream.Stream;

public abstract class AncestorSourceListDirective extends Directive {
    @Nonnull
    private List<AncestorSource> ancestorSources;

    AncestorSourceListDirective(@Nonnull String name, @Nonnull List<AncestorSource> ancestorSources) {
        super(name);
        this.ancestorSources = ancestorSources;
    }

    @Override
    public void merge(@Nonnull Directive other) {
        if (!(other instanceof AncestorSourceListDirective)) {
            throw new Error("AncestorSourceListDirective can only be merged with other AncestorSourceListDirectives");
        }
        this.ancestorSources = Directive.merge(this.ancestorSources, ((AncestorSourceListDirective) other).ancestorSources);
    }

    @Override
    public boolean equals(@Nullable Object other) {
        if (other == null || !(other instanceof AncestorSourceListDirective)) return false;
        return this.equalsHelper((AncestorSourceListDirective) other);
    }

    @Override
    public int hashCode() {
        return this.hashCodeHelper(0xC916A2D1);
    }

    @Nonnull
    @Override
    Stream<AncestorSource> values() {
        return this.ancestorSources.stream();
    }
}
