package com.shapesecurity.salvation.directives;

import com.shapesecurity.salvation.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.Set;

public class FontSrcDirective extends SourceListDirective {
    @Nonnull private static final String name = "font-src";

    public FontSrcDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
        super(FontSrcDirective.name, sourceExpressions);
    }

    @Nonnull @Override
    public Directive<SourceExpression> construct(Set<SourceExpression> newValues) {
        return new FontSrcDirective(newValues);
    }
}
