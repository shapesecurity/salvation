package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.Base64Value;
import com.shapesecurity.csp.sources.HashSource;
import com.shapesecurity.csp.sources.MatchesHash;
import com.shapesecurity.csp.sources.MatchesUrl;
import com.shapesecurity.csp.sources.SourceExpression;

import javax.annotation.Nonnull;
import java.util.List;

public abstract class SourceListDirective extends Directive<SourceExpression> {
    SourceListDirective(@Nonnull String name, @Nonnull List<SourceExpression> values) {
        super(name, values);
    }

    public boolean matchesHash(@Nonnull HashSource.HashAlgorithm algorithm, @Nonnull Base64Value hashValue) {
        return this.values()
          .filter(x -> x instanceof MatchesHash)
          .anyMatch(x -> ((MatchesHash) x).matchesHash(algorithm, hashValue));
    }

    public boolean matchesUrl(@Nonnull String origin, @Nonnull String url) {
        return this.values()
          .filter(x -> x instanceof MatchesUrl)
          .anyMatch(x -> ((MatchesUrl) x).matchesUrl(origin, url));
    }
}
