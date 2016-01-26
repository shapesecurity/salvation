package com.shapesecurity.salvation.directives;

import com.shapesecurity.salvation.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.Set;

public class ImgSrcDirective extends SourceListDirective {
    @Nonnull public static final String name = "img-src";

    public ImgSrcDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
        super(ImgSrcDirective.name, sourceExpressions);
    }

    @Nonnull @Override public Directive<SourceExpression> construct(Set<SourceExpression> newValues) {
        return new ImgSrcDirective(newValues);
    }
}
