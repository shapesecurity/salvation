package com.shapesecurity.salvation.interfaces;

import com.shapesecurity.salvation.directiveValues.MediaType;

import javax.annotation.Nonnull;

public interface MatchesMediaType {
	boolean matchesMediaType(@Nonnull MediaType mediaType);
}
