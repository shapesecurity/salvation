package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.sources.SourceExpression;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;
import java.util.stream.Stream;

public abstract class SourceListDirective extends Directive {
    @Nonnull
    private List<SourceExpression> sourceExpressions;

    SourceListDirective(@Nonnull String name, @Nonnull List<SourceExpression> sourceExpressions) {
        super(name);
        this.sourceExpressions = sourceExpressions;
    }

    @Nonnull
    @Override
    Stream<SourceExpression> values() {
        return this.sourceExpressions.stream();
    }

    @Override
    public boolean equals(@Nullable Object other) {
        if (other == null || !(other instanceof SourceListDirective)) return false;
        return this.equalsHelper((SourceListDirective) other);
    }

    @Override
    public int hashCode() {
        return this.hashCodeHelper(0x6218C185);
    }

    @Override
    public void merge(@Nonnull Directive other) {
        if (!(other instanceof SourceListDirective)) {
            throw new Error("SourceListDirective can only be merged with other SourceListDirectives");
        }
        this.sourceExpressions = Directive.merge(this.sourceExpressions, ((SourceListDirective) other).sourceExpressions);
    }
}
