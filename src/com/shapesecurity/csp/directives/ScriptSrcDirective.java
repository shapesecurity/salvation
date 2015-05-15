package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.sources.SourceExpression;

import javax.annotation.Nonnull;
import java.util.List;

public class ScriptSrcDirective extends SourceListDirective {
    @Nonnull
    public static final String name = "script-src";

    public ScriptSrcDirective(@Nonnull List<SourceExpression> sourceExpressions) {
        super(ScriptSrcDirective.name, sourceExpressions);
    }
}
