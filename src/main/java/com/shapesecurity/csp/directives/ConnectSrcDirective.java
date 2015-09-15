package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.Set;

public final class ConnectSrcDirective extends SourceListDirective {
    @Nonnull private static final String NAME = "connect-src";

    public ConnectSrcDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
        super(ConnectSrcDirective.NAME, sourceExpressions);
    }

    @Nonnull @Override
    public Directive<SourceExpression> construct(Set<SourceExpression> newValues) {
        return new ConnectSrcDirective(newValues);
    }
}
