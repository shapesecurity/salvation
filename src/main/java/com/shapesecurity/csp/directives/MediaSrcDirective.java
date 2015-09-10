package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.Set;

public class MediaSrcDirective extends SourceListDirective {
    @Nonnull private static final String name = "media-src";

    public MediaSrcDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
        super(MediaSrcDirective.name, sourceExpressions);
    }

    @Nonnull @Override
    protected Directive<SourceExpression> construct(Set<SourceExpression> newValues) {
        return new MediaSrcDirective(newValues);
    }
}
