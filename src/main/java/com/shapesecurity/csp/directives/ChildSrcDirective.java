package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.Set;

public class ChildSrcDirective extends SourceListDirective {
    @Nonnull
    private static final String NAME = "child-src";

    public ChildSrcDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
        super(ChildSrcDirective.NAME, sourceExpressions);
    }
}
