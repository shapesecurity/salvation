package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.Set;

public class FontSrcDirective extends SourceListDirective {
    @Nonnull
    private static final String name = "font-src";

    public FontSrcDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
        super(FontSrcDirective.name, sourceExpressions);
    }
}
