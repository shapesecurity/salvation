package com.shapesecurity.salvation.directives;

import com.shapesecurity.salvation.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.Set;

public class ChildSrcDirective extends SourceListDirective {
    @Nonnull private static final String NAME = "child-src";

    public ChildSrcDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
        super(ChildSrcDirective.NAME, sourceExpressions);
    }

    @Nonnull @Override public Directive<SourceExpression> construct(Set<SourceExpression> newValues) {
        return new ChildSrcDirective(newValues);
    }
}
