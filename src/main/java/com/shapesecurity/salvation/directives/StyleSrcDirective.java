package com.shapesecurity.salvation.directives;

import com.shapesecurity.salvation.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.Set;

public class StyleSrcDirective extends SourceListDirective {
    @Nonnull private static final String NAME = "style-src";

    public StyleSrcDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
        super(StyleSrcDirective.NAME, sourceExpressions);
    }

    @Nonnull @Override
    public Directive<SourceExpression> construct(Set<SourceExpression> newValues) {
        return new StyleSrcDirective(newValues);
    }
}
