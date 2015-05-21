package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.sources.SourceExpression;

import javax.annotation.Nonnull;
import java.util.List;

public class BaseUriDirective extends SourceListDirective {
    @Nonnull
    private static final String NAME = "base-uri";

    public BaseUriDirective(@Nonnull List<SourceExpression> sourceExpressions) {
        super(BaseUriDirective.NAME, sourceExpressions);
    }
}