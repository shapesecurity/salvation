package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.List;

public class DefaultSrcDirective extends SourceListDirective {
    @Nonnull
    private static final String name = "default-src";

    public DefaultSrcDirective(@Nonnull List<SourceExpression> sourceExpressions) {
        super(DefaultSrcDirective.name, sourceExpressions);
    }
}
