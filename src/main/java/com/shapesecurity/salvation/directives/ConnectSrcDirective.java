package com.shapesecurity.salvation.directives;

import com.shapesecurity.salvation.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.Set;

public final class ConnectSrcDirective extends FetchDirective {
    @Nonnull private static final String NAME = "connect-src";

    public ConnectSrcDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
        super(ConnectSrcDirective.NAME, sourceExpressions);
    }

    @Nonnull @Override public Directive<SourceExpression> construct(Set<SourceExpression> newValues) {
        return new ConnectSrcDirective(newValues);
    }
}
