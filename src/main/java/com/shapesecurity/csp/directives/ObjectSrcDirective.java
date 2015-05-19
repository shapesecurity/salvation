package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.sources.SourceExpression;

import javax.annotation.Nonnull;
import java.util.List;

public class ObjectSrcDirective extends SourceListDirective {
    @Nonnull
    private static final String name = "object-src";

    public ObjectSrcDirective(@Nonnull List<SourceExpression> sourceExpressions) {
        super(ObjectSrcDirective.name, sourceExpressions);
    }
}
