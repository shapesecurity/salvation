package com.shapesecurity.csp.sources;

import com.shapesecurity.csp.URI;

import javax.annotation.Nonnull;

public interface MatchesUri {
    boolean matchesUri(@Nonnull URI origin, @Nonnull URI uri);
}
