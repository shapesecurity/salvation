package com.shapesecurity.salvation.interfaces;

import com.shapesecurity.salvation.data.GUID;
import com.shapesecurity.salvation.data.Origin;
import com.shapesecurity.salvation.data.URI;

import javax.annotation.Nonnull;

public interface MatchesSource {
    boolean matchesSource(@Nonnull Origin origin, @Nonnull URI source);
    boolean matchesSource(@Nonnull Origin origin, @Nonnull GUID source);
}
