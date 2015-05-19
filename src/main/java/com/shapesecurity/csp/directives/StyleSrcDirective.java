package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.sources.SourceExpression;

import javax.annotation.Nonnull;
import java.util.List;

public class StyleSrcDirective extends SourceListDirective {
    @Nonnull
    private static final String name = "style-src";

    public StyleSrcDirective(@Nonnull List<SourceExpression> sourceExpressions) {
        super(StyleSrcDirective.name, sourceExpressions);
    }
}
