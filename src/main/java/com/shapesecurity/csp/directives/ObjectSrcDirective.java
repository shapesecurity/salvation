package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.Set;

public class ObjectSrcDirective extends SourceListDirective {
    @Nonnull
    private static final String name = "object-src";

    public ObjectSrcDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
        super(ObjectSrcDirective.name, sourceExpressions);
    }
}
