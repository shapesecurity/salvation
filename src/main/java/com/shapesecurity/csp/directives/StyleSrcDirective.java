package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.List;
import java.util.Set;

public class StyleSrcDirective extends SourceListDirective {
    @Nonnull
    private static final String NAME = "style-src";

    public StyleSrcDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
        super(StyleSrcDirective.NAME, sourceExpressions);
    }
}
