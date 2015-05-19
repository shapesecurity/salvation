package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.sources.SourceExpression;

import javax.annotation.Nonnull;
import java.util.List;

public class FontSrcDirective extends SourceListDirective {
    @Nonnull
    private static final String name = "font-src";

    public FontSrcDirective(@Nonnull List<SourceExpression> sourceExpressions) {
        super(FontSrcDirective.name, sourceExpressions);
    }
}
