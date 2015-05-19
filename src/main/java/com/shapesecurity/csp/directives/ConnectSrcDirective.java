package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.sources.SourceExpression;

import javax.annotation.Nonnull;
import java.util.List;

public class ConnectSrcDirective extends SourceListDirective {
    @Nonnull
    private static final String name = "connect-src";

    public ConnectSrcDirective(@Nonnull List<SourceExpression> sourceExpressions) {
        super(ConnectSrcDirective.name, sourceExpressions);
    }
}
