package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.Set;

public class ImgSrcDirective extends SourceListDirective {
    @Nonnull
    public static final String name = "img-src";

    public ImgSrcDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
        super(ImgSrcDirective.name, sourceExpressions);
    }
}