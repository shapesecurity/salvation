package com.shapesecurity.salvation.directives;

import com.shapesecurity.salvation.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.Set;

public abstract class FetchDirective extends SourceListDirective {

    public FetchDirective(@Nonnull String name, @Nonnull Set<SourceExpression> sourceExpressions) {
        super(name, sourceExpressions);
    }
}
