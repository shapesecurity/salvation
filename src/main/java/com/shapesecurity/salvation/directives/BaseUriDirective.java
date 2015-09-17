package com.shapesecurity.salvation.directives;

import com.shapesecurity.salvation.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.Set;

public class BaseUriDirective extends SourceListDirective {
    @Nonnull private static final String NAME = "base-uri";

    public BaseUriDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
        super(BaseUriDirective.NAME, sourceExpressions);
    }

    @Nonnull @Override
    public Directive<SourceExpression> construct(Set<SourceExpression> newValues) {
        return new BaseUriDirective(newValues);
    }
}
