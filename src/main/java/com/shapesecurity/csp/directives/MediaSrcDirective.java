package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.sources.SourceExpression;

import javax.annotation.Nonnull;
import java.util.List;

public class MediaSrcDirective extends SourceListDirective {
    @Nonnull
    private static final String name = "media-src";

    public MediaSrcDirective(@Nonnull List<SourceExpression> sourceExpressions) {
        super(MediaSrcDirective.name, sourceExpressions);
    }
}
