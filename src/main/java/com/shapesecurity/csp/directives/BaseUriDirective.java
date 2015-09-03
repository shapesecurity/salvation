package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.data.URI;
import com.shapesecurity.csp.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

public class BaseUriDirective extends SourceListDirective {
    @Nonnull
    private static final String NAME = "base-uri";

    public BaseUriDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
        super(BaseUriDirective.NAME, sourceExpressions);
    }

    @Nonnull
    @Override
    protected Directive<SourceExpression> construct(Set<SourceExpression> newValues) {
        return new BaseUriDirective(newValues);
    }
}