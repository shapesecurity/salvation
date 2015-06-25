package com.shapesecurity.csp.sources;

import javax.annotation.Nonnull;

public interface MatchesUrl {
    boolean matchesUrl(@Nonnull String origin, @Nonnull String url);
}
