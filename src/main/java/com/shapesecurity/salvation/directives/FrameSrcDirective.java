package com.shapesecurity.salvation.directives;

import com.shapesecurity.salvation.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.Set;

public class FrameSrcDirective extends NestedContextDirective {
    @Nonnull private static final String name = "frame-src";

    public FrameSrcDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
        super(FrameSrcDirective.name, sourceExpressions);
    }

    @Nonnull @Override public Directive<SourceExpression> construct(Set<SourceExpression> newValues) {
        return new FrameSrcDirective(newValues);
    }
}
