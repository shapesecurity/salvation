package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.sources.SourceExpression;

import javax.annotation.Nonnull;
import java.util.List;

public class BaseUriDirective extends SourceListDirective {
    @Nonnull
    private static final String name = "base-uri";

    public BaseUriDirective(@Nonnull List<SourceExpression> sourceExpressions) {
        super(BaseUriDirective.name, sourceExpressions);
    }
}