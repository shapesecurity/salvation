package com.shapesecurity.salvation.directives;

import javax.annotation.Nonnull;
import java.util.Collections;
import java.util.Set;

public class BlockAllMixedContentDirective extends Directive<DirectiveValue> {
	@Nonnull
	private static final String NAME = "block-all-mixed-content";

	public BlockAllMixedContentDirective() {
		super(BlockAllMixedContentDirective.NAME, Collections.emptySet());
	}

	@Nonnull
	@Override
	public Directive<DirectiveValue> construct(Set<DirectiveValue> newValues) {
		return this;
	}
}
