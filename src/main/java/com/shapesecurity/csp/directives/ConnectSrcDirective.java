package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.sources.SourceExpression;

import javax.annotation.Nonnull;
import java.util.List;

public final class ConnectSrcDirective extends SourceListDirective {
    @Nonnull
    private static final String NAME = "connect-src";

    public ConnectSrcDirective(@Nonnull List<SourceExpression> sourceExpressions) {
        super(ConnectSrcDirective.NAME, sourceExpressions);
    }
}
