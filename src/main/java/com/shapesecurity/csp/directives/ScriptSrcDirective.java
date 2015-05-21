package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.sources.SourceExpression;

import javax.annotation.Nonnull;
import java.util.List;

public class ScriptSrcDirective extends SourceListDirective {
    @Nonnull
    private static final String NAME = "script-src";

    public ScriptSrcDirective(@Nonnull List<SourceExpression> sourceExpressions) {
        super(ScriptSrcDirective.NAME, sourceExpressions);
    }
}
