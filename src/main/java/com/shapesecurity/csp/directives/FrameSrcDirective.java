package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.sources.SourceExpression;

import javax.annotation.Nonnull;
import java.util.List;

public class FrameSrcDirective extends SourceListDirective {
    @Nonnull
    private static final String name = "frame-src";

    public FrameSrcDirective(@Nonnull List<SourceExpression> sourceExpressions) {
        super(FrameSrcDirective.name, sourceExpressions);
    }
}
