package com.shapesecurity.salvation.directives;

import java.util.Set;

import javax.annotation.Nonnull;

import com.shapesecurity.salvation.directiveValues.SourceExpression;

public class NavigateToDirective extends SourceListDirective {
    @Nonnull private static final String name = "navigate-to";

    public NavigateToDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
        super(NavigateToDirective.name, sourceExpressions);
    }

    @Nonnull @Override public Directive<SourceExpression> construct(Set<SourceExpression> newValues) {
        return new NavigateToDirective(newValues);
    }
}
