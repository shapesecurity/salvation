package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.sources.SourceExpression;

import javax.annotation.Nonnull;
import java.util.List;

public class ChildSrcDirective extends SourceListDirective {
    @Nonnull
    public static final String name = "child-src";

    public ChildSrcDirective(@Nonnull List<SourceExpression> sourceExpressions) {
        super(ChildSrcDirective.name, sourceExpressions);
    }
}
