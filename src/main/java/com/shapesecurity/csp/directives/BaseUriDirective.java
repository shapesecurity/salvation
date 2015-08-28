package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.List;
import java.util.Set;

public class BaseUriDirective extends SourceListDirective {
    @Nonnull
    private static final String NAME = "base-uri";

    public BaseUriDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
        super(BaseUriDirective.NAME, sourceExpressions);
    }
}