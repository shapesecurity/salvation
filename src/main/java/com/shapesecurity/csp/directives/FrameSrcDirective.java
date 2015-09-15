package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.Set;

public class FrameSrcDirective extends SourceListDirective {
    @Nonnull private static final String name = "frame-src";

    public FrameSrcDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
        super(FrameSrcDirective.name, sourceExpressions);
    }

    @Nonnull @Override
    public Directive<SourceExpression> construct(Set<SourceExpression> newValues) {
        return new FrameSrcDirective(newValues);
    }
}
