package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.data.*;
import com.shapesecurity.csp.directiveValues.HashSource;
import com.shapesecurity.csp.directiveValues.HostSource;
import com.shapesecurity.csp.directiveValues.KeywordSource;
import com.shapesecurity.csp.directiveValues.SourceExpression;
import com.shapesecurity.csp.interfaces.MatchesHash;
import com.shapesecurity.csp.interfaces.MatchesNonce;
import com.shapesecurity.csp.interfaces.MatchesSource;

import javax.annotation.Nonnull;
import java.util.Collections;
import java.util.Set;

public abstract class SourceListDirective extends Directive<SourceExpression>
    implements MatchesSource, MatchesHash, MatchesNonce {
    SourceListDirective(@Nonnull String name, @Nonnull Set<SourceExpression> values) {
        super(name, values);
    }

    public boolean matchesHash(@Nonnull HashSource.HashAlgorithm algorithm,
        @Nonnull Base64Value hashValue) {
        return this.values().filter(x -> x instanceof MatchesHash)
            .anyMatch(x -> ((MatchesHash) x).matchesHash(algorithm, hashValue));
    }

    public boolean matchesSource(@Nonnull Origin origin, @Nonnull URI source) {
        return this.values().filter(x -> x instanceof MatchesSource)
            .anyMatch(x -> ((MatchesSource) x).matchesSource(origin, source));
    }

    public boolean matchesSource(@Nonnull Origin origin, @Nonnull GUID source) {
        return this.values().filter(x -> x instanceof MatchesSource)
            .anyMatch(x -> ((MatchesSource) x).matchesSource(origin, source));
    }

    public boolean matchesNonce(@Nonnull String nonce) {
        return this.values().filter(x -> x instanceof MatchesNonce)
            .anyMatch(x -> ((MatchesNonce) x).matchesNonce(nonce));
    }

    @Nonnull public Directive<SourceExpression> resolveSelf(@Nonnull Origin origin) {
        return this.bind(dv -> {
            if (dv == KeywordSource.Self) {
                if (origin instanceof SchemeHostPortTriple) {
                    SchemeHostPortTriple shpOrigin = (SchemeHostPortTriple) origin;
                    return Collections.singleton(new HostSource(shpOrigin.scheme, shpOrigin.host, shpOrigin.port, null));
                } else if (origin instanceof GUID) {
                    return Collections.EMPTY_SET;
                }
            }
            return null;
        });
    }
}
