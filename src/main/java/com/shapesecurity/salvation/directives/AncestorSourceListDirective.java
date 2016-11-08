package com.shapesecurity.salvation.directives;

import com.shapesecurity.salvation.data.GUID;
import com.shapesecurity.salvation.data.Origin;
import com.shapesecurity.salvation.data.URI;
import com.shapesecurity.salvation.directiveValues.AncestorSource;
import com.shapesecurity.salvation.interfaces.MatchesSource;

import javax.annotation.Nonnull;
import java.util.Set;

abstract class AncestorSourceListDirective extends Directive<AncestorSource> implements MatchesSource {
    AncestorSourceListDirective(@Nonnull String name, @Nonnull Set<AncestorSource> ancestorSources) {
        super(name, ancestorSources);
    }

    public boolean matchesSource(@Nonnull Origin origin, @Nonnull URI resource) {
        return this.values().filter(x -> x instanceof MatchesSource)
            .anyMatch(x -> ((MatchesSource) x).matchesSource(origin, resource));
    }

    public boolean matchesSource(@Nonnull Origin origin, @Nonnull GUID resource) {
        return this.values().filter(x -> x instanceof MatchesSource)
            .anyMatch(x -> ((MatchesSource) x).matchesSource(origin, resource));
    }
}
