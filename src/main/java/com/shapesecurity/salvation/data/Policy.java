package com.shapesecurity.salvation.data;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import com.shapesecurity.salvation.directiveValues.HashSource;
import com.shapesecurity.salvation.directiveValues.HashSource.HashAlgorithm;
import com.shapesecurity.salvation.directiveValues.HostSource;
import com.shapesecurity.salvation.directiveValues.KeywordSource;
import com.shapesecurity.salvation.directiveValues.MediaType;
import com.shapesecurity.salvation.directiveValues.NonceSource;
import com.shapesecurity.salvation.directiveValues.None;
import com.shapesecurity.salvation.directiveValues.SchemeSource;
import com.shapesecurity.salvation.directiveValues.SourceExpression;
import com.shapesecurity.salvation.directives.*;
import com.shapesecurity.salvation.interfaces.Show;

public class Policy implements Show {

	private static final Set<SourceExpression> justNone = Collections.singleton(None.INSTANCE);
	@Nonnull
	private final Map<Class<?>, Directive<? extends DirectiveValue>> directives;
	@Nonnull
	private Origin origin;

	public Policy(@Nonnull Origin origin) {
		this.directives = new LinkedHashMap<>();
		this.origin = origin;
	}

	@Nonnull
	public Origin getOrigin() {
		return origin;
	}

	public void setOrigin(@Nonnull Origin origin) {
		this.origin = origin;
	}

	public void intersect(@Nonnull Policy other) {
		this.checkForMergeValidity();
		other.checkForMergeValidity();

		this.resolveSelf();
		other.resolveSelf();

		this.expandDefaultSrc();
		other.expandDefaultSrc();

		for (Map.Entry<Class<?>, Directive<? extends DirectiveValue>> entry : other.directives.entrySet()) {
			this.intersectDirectivePrivate(entry.getValue());
		}

		this.optimise();
		other.optimise();
	}

	public void union(@Nonnull Policy other) {
		this.checkForMergeValidity();
		other.checkForMergeValidity();

		this.resolveSelf();
		other.resolveSelf();

		this.expandDefaultSrc();
		other.expandDefaultSrc();

		for (Map.Entry<Class<?>, Directive<? extends DirectiveValue>> entry : other.directives.entrySet()) {
			this.unionDirectivePrivate(entry.getValue());
		}
		this.directives.entrySet().removeIf(entry -> !other.directives.containsKey(entry.getKey()));

		this.optimise();
		other.optimise();
	}

	private void checkForMergeValidity() {
		if (this.directives.containsKey(ReportUriDirective.class)) {
			throw new IllegalArgumentException("Cannot merge policies if either policy contains a report-uri directive.");
		}

		if (this.directives.containsKey(ReportToDirective.class)) {
			throw new IllegalArgumentException("Cannot merge policies if either policy contains a report-to directive.");
		}

		if (this.directives.containsKey(ReferrerDirective.class)) {
			throw new IllegalArgumentException("Cannot merge policies if either policy contains a referrer directive.");
		}
	}

	private void resolveSelf() {
		for (Map.Entry<Class<?>, Directive<? extends DirectiveValue>> entry : this.directives.entrySet()) {
			Directive<? extends DirectiveValue> directive = entry.getValue();
			if (directive instanceof SourceListDirective) {
				this.directives.put(entry.getKey(), ((SourceListDirective) directive).resolveSelf(this.origin));
			}
		}
	}

	private void expandDefaultSrc() {
		// This is a special case because worker-src falls back to child-src before script-src,
		// but child-src does _not_ fall back to script-src.
		// Hence this logic needs to happen before expanding anything into child-src, to ensure that
		// if script-src is present and child-src is not, worker-src comes from script-src rather than default-src.
		if (this.directives.containsKey(ScriptSrcDirective.class) && !this.directives.containsKey(ChildSrcDirective.class) && !this.directives.containsKey(WorkerSrcDirective.class)) {
			ScriptSrcDirective scriptSrcDirective = this.getDirectiveByType(ScriptSrcDirective.class);
			Set<SourceExpression> sources = scriptSrcDirective.values().collect(Collectors.toCollection(LinkedHashSet::new));
			this.directives.put(WorkerSrcDirective.class, new WorkerSrcDirective(sources));
		}

		DefaultSrcDirective defaultSrcDirective = this.getDirectiveByType(DefaultSrcDirective.class);
		Set<SourceExpression> defaultSources;
		if (defaultSrcDirective != null) {

			defaultSources = defaultSrcDirective.values().collect(Collectors.toCollection(LinkedHashSet::new));

			if (!this.directives.containsKey(ScriptSrcDirective.class)) {
				this.directives.put(ScriptSrcDirective.class, new ScriptSrcDirective(defaultSources));
			}
			if (!this.directives.containsKey(StyleSrcDirective.class)) {
				this.directives.put(StyleSrcDirective.class, new StyleSrcDirective(defaultSources));
			}
			if (!this.directives.containsKey(ImgSrcDirective.class)) {
				this.directives.put(ImgSrcDirective.class, new ImgSrcDirective(defaultSources));
			}
			if (!this.directives.containsKey(ChildSrcDirective.class)) {
				this.directives.put(ChildSrcDirective.class, new ChildSrcDirective(defaultSources));
			}
			if (!this.directives.containsKey(ConnectSrcDirective.class)) {
				this.directives.put(ConnectSrcDirective.class, new ConnectSrcDirective(defaultSources));
			}
			if (!this.directives.containsKey(FontSrcDirective.class)) {
				this.directives.put(FontSrcDirective.class, new FontSrcDirective(defaultSources));
			}
			if (!this.directives.containsKey(MediaSrcDirective.class)) {
				this.directives.put(MediaSrcDirective.class, new MediaSrcDirective(defaultSources));
			}
			if (!this.directives.containsKey(ObjectSrcDirective.class)) {
				this.directives.put(ObjectSrcDirective.class, new ObjectSrcDirective(defaultSources));
			}
			if (!this.directives.containsKey(ManifestSrcDirective.class)) {
				this.directives.put(ManifestSrcDirective.class, new ManifestSrcDirective(defaultSources));
			}
			if (!this.directives.containsKey(PrefetchSrcDirective.class)) {
				this.directives.put(PrefetchSrcDirective.class, new PrefetchSrcDirective(defaultSources));
			}
		}

		// expand child-src
		if (this.directives.containsKey(ChildSrcDirective.class) && !this.directives.containsKey(FrameSrcDirective.class)) {
			ChildSrcDirective childSrcDirective = this.getDirectiveByType(ChildSrcDirective.class);
			Set<Directive> expandedDirectives = expandDirective(childSrcDirective);
			expandedDirectives.forEach(this::insert);
		}

		// expand script-src
		if (this.directives.containsKey(ScriptSrcDirective.class)) {
			ScriptSrcDirective scriptSrcDirective = this.getDirectiveByType(ScriptSrcDirective.class);
			Set<Directive> expandedDirectives = expandDirective(scriptSrcDirective);
			expandedDirectives.forEach(this::insert);
		}

		// expand style-src
		if (this.directives.containsKey(StyleSrcDirective.class)) {
			StyleSrcDirective styleSrcDirective = this.getDirectiveByType(StyleSrcDirective.class);
			Set<Directive> expandedDirectives = expandDirective(styleSrcDirective);
			expandedDirectives.forEach(this::insert);
		}

	}

	private <V extends SourceExpression, T extends Directive<V>> void eliminateRedundantSourceExpression(
			@Nonnull Set<SourceExpression> defaultSources, Class<T> type) {
		T directive = this.getDirectiveByType(type);
		if (directive != null) {
			Set<SourceExpression> values = directive.values().collect(Collectors.toCollection(LinkedHashSet::new));
			if (defaultSources.equals(values)
					|| (defaultSources.isEmpty() || defaultSources.equals(Policy.justNone)) && (values.isEmpty() || values
					.equals(Policy.justNone))) {
				this.directives.remove(type);
			}
		}
	}

	public void optimise() {
		for (Map.Entry<Class<?>, Directive<? extends DirectiveValue>> entry : this.directives.entrySet()) {
			Directive<? extends DirectiveValue> directive = entry.getValue();
			if (directive instanceof SourceListDirective) {
				SourceListDirective sourceListDirective = (SourceListDirective) directive;
				Optional<SourceExpression> star =
						sourceListDirective.values().filter(x -> x instanceof HostSource && ((HostSource) x).isWildcard())
								.findAny();
				if (star.isPresent()) {
					Set<SourceExpression> newSources = sourceListDirective.values()
							// * remove all other host sources in a source list that contains *
							.filter(x -> !(x instanceof HostSource))
							// * remove network-schemes in source list that contains *
							.filter(x -> !(x instanceof SchemeSource) || !((SchemeSource) x).matchesNetworkScheme())
							// * remove 'unsafe-inline' if source list contains hash or nonce
							.filter(x -> !((x == KeywordSource.UnsafeInline) &&
									(sourceListDirective.containsNonceSource() || sourceListDirective.containsHashSource())))
							.collect(Collectors.toCollection(LinkedHashSet::new));
					newSources.add(star.get());
					this.directives.put(entry.getKey(), sourceListDirective.construct(newSources));
				} else {
					this.directives.put(entry.getKey(), sourceListDirective.bind(dv -> {
						// * replace host-sources that are equivalent to origin with 'self' keyword-source
						if (dv instanceof HostSource &&
								this.origin instanceof SchemeHostPortTriple && !((HostSource) dv).hasPath() &&
								((HostSource) dv).matchesOnlyOrigin((SchemeHostPortTriple) this.origin)) {
							return Collections.singleton(KeywordSource.Self);
						}
						// * replace 'none' with empty
						if (dv == None.INSTANCE) {
							return Collections.emptySet();
						}
						// no change
						return null;
					}));
				}
			}
		}

		// merge into script-src if script-src-elem and script-src-attr are identical and worker-src is present
		ScriptSrcElemDirective scriptSrcElemDirective = this.getDirectiveByType(ScriptSrcElemDirective.class);
		ScriptSrcAttrDirective scriptSrcAttrDirective = this.getDirectiveByType(ScriptSrcAttrDirective.class);
		WorkerSrcDirective workerSrcDirective = this.getDirectiveByType(WorkerSrcDirective.class);
		if (scriptSrcElemDirective != null && scriptSrcAttrDirective != null && workerSrcDirective != null) {
			Set<SourceExpression> a = scriptSrcElemDirective.values().filter(x -> x != KeywordSource.UnsafeEval).collect(Collectors.toCollection(LinkedHashSet::new));
			Set<SourceExpression> b = scriptSrcAttrDirective.values().filter(x -> x != KeywordSource.UnsafeEval).collect(Collectors.toCollection(LinkedHashSet::new));
			if (a.equals(b)) {
				ScriptSrcDirective scriptSrcDirective = this.getDirectiveByType(ScriptSrcDirective.class);
				Set<SourceExpression> scriptSources = a;
				if (scriptSrcDirective != null && scriptSrcDirective.contains(KeywordSource.UnsafeEval)) {
					// unsafe-eval only applies when in script-src, not script-src-elem or script-src-attr.
					// but if both of those and worker-src are present, script-src has no other effect.
					scriptSources.add(KeywordSource.UnsafeEval);
				}
				scriptSrcDirective = new ScriptSrcDirective(scriptSources);
				this.directives.put(ScriptSrcDirective.class, scriptSrcDirective);
				this.directives.remove(ScriptSrcElemDirective.class);
				this.directives.remove(ScriptSrcAttrDirective.class);
			}
		}

		// merge into style-src if style-src-elem and style-src-attr are identical
		StyleSrcElemDirective styleSrcElemDirective = this.getDirectiveByType(StyleSrcElemDirective.class);
		StyleSrcAttrDirective styleSrcAttrDirective = this.getDirectiveByType(StyleSrcAttrDirective.class);
		if (styleSrcElemDirective != null && styleSrcAttrDirective != null) {
			Set<SourceExpression> a = styleSrcElemDirective.values().collect(Collectors.toCollection(LinkedHashSet::new));
			Set<SourceExpression> b = styleSrcAttrDirective.values().collect(Collectors.toCollection(LinkedHashSet::new));
			if (a.equals(b)) {
				StyleSrcDirective styleSrcDirective = this.getDirectiveByType(StyleSrcDirective.class);
				Set<SourceExpression> styleSources = a;
				if (styleSrcDirective != null) {
					styleSources.addAll(styleSrcDirective.values().collect(Collectors.toCollection(LinkedHashSet::new)));
				}
				styleSrcDirective = new StyleSrcDirective(styleSources);
				this.directives.put(StyleSrcDirective.class, styleSrcDirective);
				this.directives.remove(StyleSrcElemDirective.class);
				this.directives.remove(StyleSrcAttrDirective.class);
			}
		}

		ChildSrcDirective childSrcDirective = this.getDirectiveByType(ChildSrcDirective.class);
		if (childSrcDirective != null) {
			Set<SourceExpression> childSources = childSrcDirective.values().collect(Collectors.toCollection(LinkedHashSet::new));
			// * remove worker source directive if equivalent to child-src
			this.eliminateRedundantSourceExpression(childSources, WorkerSrcDirective.class);
			// * remove frame source directive if equivalent to child-src
			this.eliminateRedundantSourceExpression(childSources, FrameSrcDirective.class);
		}

		ScriptSrcDirective scriptSrcDirective = this.getDirectiveByType(ScriptSrcDirective.class);
		if (scriptSrcDirective != null) {
			Set<SourceExpression> scriptSources = scriptSrcDirective.values().collect(Collectors.toCollection(LinkedHashSet::new));
			// * remove worker source directive if equivalent to script-src
			this.eliminateRedundantSourceExpression(scriptSources, WorkerSrcDirective.class);
			// * remove script-src-elem and script-src-attr directives if equivalent to script-src
			this.eliminateRedundantSourceExpression(scriptSources, ScriptSrcElemDirective.class);
			this.eliminateRedundantSourceExpression(scriptSources, ScriptSrcAttrDirective.class);
		}

		StyleSrcDirective styleSrcDirective = this.getDirectiveByType(StyleSrcDirective.class);
		if (styleSrcDirective != null) {
			Set<SourceExpression> styleSources = styleSrcDirective.values().collect(Collectors.toCollection(LinkedHashSet::new));
			// * remove style-src-elem and style-src-attr directives if equivalent to script-src
			this.eliminateRedundantSourceExpression(styleSources, StyleSrcElemDirective.class);
			this.eliminateRedundantSourceExpression(styleSources, StyleSrcAttrDirective.class);
		}


		DefaultSrcDirective defaultSrcDirective = this.getDirectiveByType(DefaultSrcDirective.class);

		Set<SourceExpression> defaultSources;

		if (defaultSrcDirective != null) {
			defaultSources = defaultSrcDirective.values().collect(Collectors.toCollection(LinkedHashSet::new));


			// * remove source directives that are equivalent to default-src

			Directive.getFetchDirectives().forEach(x -> this.eliminateRedundantSourceExpression(defaultSources, x));

			// * remove default-src nonces if the policy contains both script-src and style-src directives
			if (this.directives.containsKey(ScriptSrcDirective.class) && this.directives
					.containsKey(StyleSrcDirective.class)) {
				defaultSources.removeIf(x -> x instanceof NonceSource);
				defaultSrcDirective = new DefaultSrcDirective(defaultSources);
				this.directives.put(DefaultSrcDirective.class, defaultSrcDirective);
			}


			// * remove unnecessary default-src directives if all source directives exist
			if (all(Directive.getFetchDirectives(), this.directives::containsKey)) {
				this.directives.remove(DefaultSrcDirective.class);
			}
		}
	}

	private static <A> boolean all(List<A> list, Function<A, Boolean> predicate) {
		for (A a : list) {
			if (!predicate.apply(a)) {
				return false;
			}
		}
		return true;
	}

	public boolean containsFetchDirective() {
		return directives.values().stream().anyMatch(x -> x instanceof FetchDirective);
	}

	public void postProcessOptimisation() {

		DefaultSrcDirective defaultSrcDirective;

		int directiveCount = this.directives.size();

		// below optimisations kick in when there are two or more directives
		if (directiveCount < 2) {
			return;
		}
		// move source-expressions to default-src if they exist in every fetch directive
		SourceListDirective prevDirective = null;
		int fetchDirectiveCount = 0;
		boolean isfetchSourceListIdentical = true;
		for (Map.Entry<Class<?>, Directive<? extends DirectiveValue>> entry : this.directives.entrySet()) {
			Directive<? extends DirectiveValue> directive = entry.getValue();
			if (directive instanceof FetchDirective) {
				fetchDirectiveCount++;
				if (prevDirective != null) {
					if (!prevDirective.sourceListEquals(directive)) {
						isfetchSourceListIdentical = false;
						break;
					}
				}
				prevDirective = (SourceListDirective) directive;
			}
		}

		// remove all fetch directives and replace with default-src
		if (prevDirective != null && fetchDirectiveCount == Directive.FETCH_DIRECIVE_COUNT && isfetchSourceListIdentical) {
			Set<SourceExpression> combinedSources = prevDirective.values().collect(Collectors.toCollection(LinkedHashSet::new));
			defaultSrcDirective = new DefaultSrcDirective(combinedSources);
			Directive.getFetchDirectives().forEach(x -> this.directives.remove(x));
			this.directives.put(DefaultSrcDirective.class, defaultSrcDirective);
		}

		// if policy contains only fetch directives and those are script-src and style-src with identical source-lists,
		// and source-lists contain solely keyword-source or nonce-source, source-list can be moved to default-src
		if (directiveCount == 2 && this.directives.containsKey(ScriptSrcDirective.class) && this.directives
				.containsKey(StyleSrcDirective.class)) {
			ScriptSrcDirective scriptSrcDirective = this.getDirectiveByType(ScriptSrcDirective.class);
			StyleSrcDirective styleSrcDirective = this.getDirectiveByType(StyleSrcDirective.class);
			if (scriptSrcDirective.sourceListEquals(styleSrcDirective) && scriptSrcDirective.containsKeywordsAndNoncesOnly()) {
				defaultSrcDirective = new DefaultSrcDirective(scriptSrcDirective.values().collect(Collectors.toCollection(LinkedHashSet::new)));
				this.directives.remove(ScriptSrcDirective.class);
				this.directives.remove(StyleSrcDirective.class);
				this.directives.put(DefaultSrcDirective.class, defaultSrcDirective);
			}
		}
	}

	public void unionDirective(@Nonnull Directive<? extends DirectiveValue> directive) {
		this.resolveSelf();
		if (directive instanceof SourceListDirective) {
			directive = ((SourceListDirective) directive).resolveSelf(this.origin);
		}
		if (!(directive instanceof DefaultSrcDirective)) {
			this.expandDefaultSrc();
		}
		Set<Directive> expandedDirectives = expandDirective(directive);
		expandedDirectives.forEach(x -> this.unionDirectivePrivate(x));
		this.optimise();
	}

	public void intersectDirective(@Nonnull Directive<? extends DirectiveValue> directive) {
		this.resolveSelf();
		if (directive instanceof SourceListDirective) {
			directive = ((SourceListDirective) directive).resolveSelf(this.origin);
		}
		if (!(directive instanceof DefaultSrcDirective)) {
			this.expandDefaultSrc();
		}
		Set<Directive> expandedDirectives = expandDirective(directive);
		expandedDirectives.forEach(x -> this.intersectDirectivePrivate(x));
		this.optimise();
	}

	private static Set<Directive> expandDirective(@Nonnull Directive<? extends DirectiveValue> directive) {
		if (!(directive instanceof FetchDirective)) {
			return Collections.singleton(directive);
		}
		Set<Directive> directives = new LinkedHashSet<>();
		directives.add(directive);
		Stream<SourceExpression> stream = (Stream<SourceExpression>) directive.values();
		Set<SourceExpression> sources = stream.collect(Collectors.toCollection(LinkedHashSet::new));
		if (directive instanceof ChildSrcDirective) {
			directives.add(new FrameSrcDirective(sources));
			directives.add(new WorkerSrcDirective(sources));
		} else if (directive instanceof ScriptSrcDirective) {
			directives.add(new ScriptSrcElemDirective(sources));
			directives.add(new ScriptSrcAttrDirective(sources));
			directives.add(new WorkerSrcDirective(sources));
		} else if (directive instanceof StyleSrcDirective) {
			directives.add(new StyleSrcElemDirective(sources));
			directives.add(new StyleSrcAttrDirective(sources));
		}
		return directives;
	}

	// union a directive if it does not exist; used for policy manipulation and composition
	private <V extends DirectiveValue, T extends Directive<V>> void unionDirectivePrivate(@Nonnull T directive) {
		@SuppressWarnings("unchecked") T oldDirective = (T) this.directives.get(directive.getClass());
		if (oldDirective != null) {
			oldDirective.union(directive);
		}
	}

	private <V extends DirectiveValue, T extends Directive<V>> void intersectDirectivePrivate(@Nonnull T directive) {
		@SuppressWarnings("unchecked") T oldDirective = (T) this.directives.get(directive.getClass());
		if (oldDirective != null) {
			oldDirective.intersect(directive);
		} else {
			this.directives.put(directive.getClass(), directive);
		}
	}

	// only add a directive if it doesn't exist; used for handling duplicate directives in CSP headers
	public <V extends DirectiveValue, T extends Directive<V>> void addDirective(@Nonnull T d) {
		Directive<? extends DirectiveValue> directive = this.directives.get(d.getClass());
		if (directive == null) {
			this.directives.put(d.getClass(), d);
			this.expandDefaultSrc();
			this.resolveSelf();
			this.optimise();
		}
	}

	// differs from the above in that it will override things
	public void addDirectives(@Nonnull Iterable<Directive<? extends DirectiveValue>> directives) {
		for (Directive<? extends DirectiveValue> d : directives) {
			this.directives.put(d.getClass(), d);
		}
		this.expandDefaultSrc();
		this.resolveSelf();
		this.optimise();
	}

	@Nonnull
	public Collection<Directive<? extends DirectiveValue>> getDirectives() {
		return this.directives.values();
	}

	@SuppressWarnings("unchecked")
	@Nullable
	public <V extends DirectiveValue, T extends Directive<V>> T getDirectiveByType(@Nonnull Class<T> type) {
		T d = (T) this.directives.get(type);
		if (d == null) {
			return null;
		}
		return d;
	}

	@Override
	public boolean equals(@Nullable Object other) {
		if (other == null || !(other instanceof Policy)) {
			return false;
		}
		return this.directives.size() == ((Policy) other).directives.size() && this.directives
				.equals(((Policy) other).directives);
	}

	@Override
	public int hashCode() {
		return this.directives.values().stream().map(Object::hashCode).reduce(0x19E465E0, (a, b) -> a ^ b);
	}

	@Nonnull
	@Override
	public String show() {
		StringBuilder sb = new StringBuilder();
		if (this.directives.isEmpty()) {
			return "";
		}
		boolean first = true;
		for (Directive<?> d : this.directives.values()) {
			if (!first) {
				sb.append("; ");
			}
			first = false;
			sb.append(d.show());
		}
		return sb.toString();
	}

	private boolean defaultsAllowAttributeWithHash(@Nonnull HashAlgorithm algorithm, @Nonnull Base64Value hashValue) {
		if (!this.defaultsHaveUnsafeHashes()) {
			return false;
		}
		DefaultSrcDirective defaultSrcDirective = this.getDirectiveByType(DefaultSrcDirective.class);
		if (defaultSrcDirective == null) {
			return true;
		}
		return defaultSrcDirective.matchesHash(algorithm, hashValue);
	}

	private boolean defaultsAllowHash(@Nonnull HashAlgorithm algorithm, @Nonnull Base64Value hashValue) {
		if (this.defaultsHaveUnsafeInline() && !this.defaultsHaveNonceSource() && !this.defaultsHaveHashSource() && !this.defaultsHaveStrictDynamic()) {
			return true;
		}
		DefaultSrcDirective defaultSrcDirective = this.getDirectiveByType(DefaultSrcDirective.class);
		if (defaultSrcDirective == null) {
			return true;
		}
		return defaultSrcDirective.matchesHash(algorithm, hashValue);
	}

	private boolean defaultsAllowNonce(@Nonnull String nonce) {
		if (this.defaultsHaveUnsafeInline() && !this.defaultsHaveHashSource() && !this.defaultsHaveNonceSource() && !this.defaultsHaveStrictDynamic()) {
			return true;
		}
		DefaultSrcDirective defaultSrcDirective = this.getDirectiveByType(DefaultSrcDirective.class);
		if (defaultSrcDirective == null) {
			return true;
		}
		return defaultSrcDirective.matchesNonce(nonce);
	}

	private boolean defaultsAllowSource(@Nonnull URI source) {
		DefaultSrcDirective defaultSrcDirective = this.getDirectiveByType(DefaultSrcDirective.class);
		if (defaultSrcDirective == null) {
			return true;
		}
		return defaultSrcDirective.matchesSource(this.origin, source);
	}

	private boolean defaultsAllowSource(@Nonnull GUID source) {
		DefaultSrcDirective defaultSrcDirective = this.getDirectiveByType(DefaultSrcDirective.class);
		if (defaultSrcDirective == null) {
			return true;
		}
		return defaultSrcDirective.matchesSource(this.origin, source);
	}

	private boolean defaultsHaveUnsafeInline() {
		DefaultSrcDirective defaultSrcDirective = this.getDirectiveByType(DefaultSrcDirective.class);
		if (defaultSrcDirective == null) {
			return false;
		}
		return defaultSrcDirective.values().anyMatch(x -> x == KeywordSource.UnsafeInline);
	}

	private boolean defaultsHaveUnsafeHashes() {
		DefaultSrcDirective defaultSrcDirective = this.getDirectiveByType(DefaultSrcDirective.class);
		if (defaultSrcDirective == null) {
			return false;
		}
		return defaultSrcDirective.values().anyMatch(x -> x == KeywordSource.UnsafeHashes);
	}

	private boolean defaultsHaveNonceSource() {
		DefaultSrcDirective defaultSrcDirective = this.getDirectiveByType(DefaultSrcDirective.class);
		if (defaultSrcDirective == null) {
			return false;
		}
		return defaultSrcDirective.values().anyMatch(x -> x instanceof NonceSource);
	}

	private boolean defaultsHaveHashSource() {
		DefaultSrcDirective defaultSrcDirective = this.getDirectiveByType(DefaultSrcDirective.class);
		if (defaultSrcDirective == null) {
			return false;
		}
		return defaultSrcDirective.values().anyMatch(x -> x instanceof HashSource);
	}

	private boolean defaultsHaveStrictDynamic() {
		DefaultSrcDirective defaultSrcDirective = this.getDirectiveByType(DefaultSrcDirective.class);
		if (defaultSrcDirective == null) {
			return false;
		}
		return defaultSrcDirective.values().anyMatch(x -> x == KeywordSource.StrictDynamic);
	}

	public boolean hasStrictDynamic() {
		ScriptSrcDirective scriptSrcDirective = this.getDirectiveByType(ScriptSrcDirective.class);
		if (scriptSrcDirective == null) {
			return this.defaultsHaveStrictDynamic();
		}
		return scriptSrcDirective.values().anyMatch(x -> x == KeywordSource.StrictDynamic);
	}

	public boolean allowsImgFromSource(@Nonnull URI source) {
		ImgSrcDirective imgSrcDirective = this.getDirectiveByType(ImgSrcDirective.class);
		if (imgSrcDirective == null) {
			return this.defaultsAllowSource(source);
		}
		return imgSrcDirective.matchesSource(this.origin, source);
	}

	public boolean allowsImgFromSource(@Nonnull GUID source) {
		ImgSrcDirective imgSrcDirective = this.getDirectiveByType(ImgSrcDirective.class);
		if (imgSrcDirective == null) {
			return this.defaultsAllowSource(source);
		}
		return imgSrcDirective.matchesSource(this.origin, source);
	}

	public boolean allowsPrefetchFromSource(@Nonnull URI source) {
		PrefetchSrcDirective prefetchSrcDirective = this.getDirectiveByType(PrefetchSrcDirective.class);
		if (prefetchSrcDirective == null) {
			return this.defaultsAllowSource(source);
		}
		return prefetchSrcDirective.matchesSource(this.origin, source);
	}

	public boolean allowsPrefetchFromSource(@Nonnull GUID source) {
		PrefetchSrcDirective PrefetchSrcDirective = this.getDirectiveByType(PrefetchSrcDirective.class);
		if (PrefetchSrcDirective == null) {
			return this.defaultsAllowSource(source);
		}
		return PrefetchSrcDirective.matchesSource(this.origin, source);
	}

	public boolean allowsScriptFromSource(@Nonnull URI source) {
		ScriptSrcDirective scriptSrcDirective = this.getDirectiveByType(ScriptSrcDirective.class);
		if (scriptSrcDirective == null) {
			return this.defaultsAllowSource(source);
		}
		return scriptSrcDirective.matchesSource(this.origin, source);
	}

	public boolean allowsScriptFromSource(@Nonnull GUID source) {
		ScriptSrcDirective scriptSrcDirective = this.getDirectiveByType(ScriptSrcDirective.class);
		if (scriptSrcDirective == null) {
			return this.defaultsAllowSource(source);
		}
		return scriptSrcDirective.matchesSource(this.origin, source);
	}

	public boolean allowsStyleFromSource(@Nonnull URI source) {
		StyleSrcDirective styleSrcDirective = this.getDirectiveByType(StyleSrcDirective.class);
		if (styleSrcDirective == null) {
			return this.defaultsAllowSource(source);
		}
		return styleSrcDirective.matchesSource(this.origin, source);
	}

	public boolean allowsStyleFromSource(@Nonnull GUID source) {
		StyleSrcDirective styleSrcDirective = this.getDirectiveByType(StyleSrcDirective.class);
		if (styleSrcDirective == null) {
			return this.defaultsAllowSource(source);
		}
		return styleSrcDirective.matchesSource(this.origin, source);
	}

	public boolean allowsConnectTo(@Nonnull URI source) {
		ConnectSrcDirective connectSrcDirective = this.getDirectiveByType(ConnectSrcDirective.class);
		if (connectSrcDirective == null) {
			return this.defaultsAllowSource(source);
		}
		return connectSrcDirective.matchesSource(this.origin, source);
	}

	public boolean allowsConnectTo(@Nonnull GUID source) {
		ConnectSrcDirective connectSrcDirective = this.getDirectiveByType(ConnectSrcDirective.class);
		if (connectSrcDirective == null) {
			return this.defaultsAllowSource(source);
		}
		return connectSrcDirective.matchesSource(this.origin, source);
	}

	public boolean allowsStyleWithHash(@Nonnull HashAlgorithm algorithm, @Nonnull Base64Value hashValue) {
		if (this.allowsUnsafeInlineStyle()) {
			return true;
		}

		StyleSrcElemDirective styleSrcElemDirective = this.getDirectiveByType(StyleSrcElemDirective.class);
		if (styleSrcElemDirective != null) {
			return styleSrcElemDirective.matchesHash(algorithm, hashValue);
		}

		StyleSrcDirective styleSrcDirective = this.getDirectiveByType(StyleSrcDirective.class);
		if (styleSrcDirective != null) {
			return styleSrcDirective.matchesHash(algorithm, hashValue);
		}

		return this.defaultsAllowHash(algorithm, hashValue);

	}

	public boolean allowsScriptWithHash(@Nonnull HashAlgorithm algorithm, @Nonnull Base64Value hashValue) {
		if (this.allowsUnsafeInlineScript()) {
			return true;
		}
		ScriptSrcElemDirective scriptSrcElemDirective = this.getDirectiveByType(ScriptSrcElemDirective.class);
		if (scriptSrcElemDirective != null) {
			return scriptSrcElemDirective.matchesHash(algorithm, hashValue);
		}

		ScriptSrcDirective scriptSrcDirective = this.getDirectiveByType(ScriptSrcDirective.class);
		if (scriptSrcDirective != null) {
			return scriptSrcDirective.matchesHash(algorithm, hashValue);
		}

		return this.defaultsAllowHash(algorithm, hashValue);
	}

	public boolean allowsScriptAttributeWithHash(@Nonnull HashAlgorithm algorithm, @Nonnull Base64Value hashValue) {
		if (!this.haveUnsafeScriptHashes()) {
			return false;
		}
		ScriptSrcAttrDirective scriptSrcAttrDirective = this.getDirectiveByType(ScriptSrcAttrDirective.class);
		if (scriptSrcAttrDirective == null) {
			ScriptSrcDirective scriptSrcDirective = this.getDirectiveByType(ScriptSrcDirective.class);
			if (scriptSrcDirective == null) {
				return this.defaultsAllowAttributeWithHash(algorithm, hashValue);
			}
			return scriptSrcDirective.matchesHash(algorithm, hashValue);
		}
		return scriptSrcAttrDirective.matchesHash(algorithm, hashValue);
	}

	public boolean allowsStyleAttributeWithHash(@Nonnull HashAlgorithm algorithm, @Nonnull Base64Value hashValue) {
		if (!this.haveUnsafeStyleHashes()) {
			return false;
		}
		StyleSrcAttrDirective styleSrcAttrDirective = this.getDirectiveByType(StyleSrcAttrDirective.class);
		if (styleSrcAttrDirective == null) {
			StyleSrcDirective styleSrcDirective = this.getDirectiveByType(StyleSrcDirective.class);
			if (styleSrcDirective == null) {
				return this.defaultsAllowAttributeWithHash(algorithm, hashValue);
			}
			return styleSrcDirective.matchesHash(algorithm, hashValue);
		}
		return styleSrcAttrDirective.matchesHash(algorithm, hashValue);
	}

	public boolean allowsUnsafeInlineScript() {
		return containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.UnsafeInline) &&
				!containsSourceExpression(ScriptSrcDirective.class, x -> x instanceof NonceSource) &&
				!containsSourceExpression(ScriptSrcDirective.class, x -> x instanceof HashSource) &&
				!containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.StrictDynamic);

	}

	public boolean haveUnsafeScriptHashes() {
		return containsSourceExpression(ScriptSrcAttrDirective.class, x -> x == KeywordSource.UnsafeHashes) ||
				containsSourceExpression(ScriptSrcDirective.class, x -> x == KeywordSource.UnsafeHashes) ||
				defaultsHaveUnsafeHashes();
	}

	public boolean haveUnsafeStyleHashes() {
		return containsSourceExpression(StyleSrcAttrDirective.class, x -> x == KeywordSource.UnsafeHashes) ||
				containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.UnsafeHashes) ||
				defaultsHaveUnsafeHashes();
	}

	public <T extends SourceListDirective> boolean containsSourceExpression(Class<T> type, @Nonnull Predicate<SourceExpression> predicate) {
		T d = this.getDirectiveByType(type);
		if (d == null) {
			return type != DefaultSrcDirective.class && this.containsSourceExpression(DefaultSrcDirective.class, predicate);
		}
		return d.values().anyMatch(predicate);
	}

	@Nonnull
	public <T extends SourceListDirective> Stream<SourceExpression> getEffectiveSourceExpressions(Class<T> type) {
		SourceListDirective d = this.getDirectiveByType(type);
		if (d == null && type != DefaultSrcDirective.class) {
			d = this.getDirectiveByType(DefaultSrcDirective.class);
		}
		return d != null ? d.values() : Stream.empty();
	}

	public boolean allowsUnsafeInlineStyle() {
		return containsSourceExpression(StyleSrcDirective.class, x -> x == KeywordSource.UnsafeInline) &&
				!containsSourceExpression(StyleSrcDirective.class, x -> x instanceof NonceSource) &&
				!containsSourceExpression(StyleSrcDirective.class, x -> x instanceof HashSource);
	}

	public boolean allowsPlugin(@Nonnull MediaType mediaType) {
		PluginTypesDirective pluginTypesDirective = this.getDirectiveByType(PluginTypesDirective.class);
		if (pluginTypesDirective == null) {
			return false;
		}
		return pluginTypesDirective.matchesMediaType(mediaType);
	}

	public boolean allowsScriptWithNonce(@Nonnull String nonce) {
		if (this.allowsUnsafeInlineScript()) {
			return true;
		}
		ScriptSrcElemDirective scriptSrcElemDirective = this.getDirectiveByType(ScriptSrcElemDirective.class);
		if (scriptSrcElemDirective != null) {
			return scriptSrcElemDirective.matchesNonce(nonce);
		}

		ScriptSrcDirective scriptSrcDirective = this.getDirectiveByType(ScriptSrcDirective.class);
		if (scriptSrcDirective != null) {
			return scriptSrcDirective.matchesNonce(nonce);
		}
		return this.defaultsAllowNonce(nonce);
	}

	public boolean allowsScriptWithNonce(@Nonnull Base64Value nonce) {
		return this.allowsScriptWithNonce(nonce.value);
	}

	public boolean allowsStyleWithNonce(@Nonnull String nonce) {
		if (this.allowsUnsafeInlineStyle()) {
			return true;
		}
		StyleSrcElemDirective styleSrcElemDirective = this.getDirectiveByType(StyleSrcElemDirective.class);
		if (styleSrcElemDirective != null) {
			return styleSrcElemDirective.matchesNonce(nonce);
		}

		StyleSrcDirective styleSrcDirective = this.getDirectiveByType(StyleSrcDirective.class);
		if (styleSrcDirective != null) {
			return styleSrcDirective.matchesNonce(nonce);
		}
		return this.defaultsAllowNonce(nonce);
	}

	public boolean allowsStyleWithNonce(@Nonnull Base64Value nonce) {
		return this.allowsStyleWithNonce(nonce.value);
	}


	public boolean allowsChildFromSource(@Nonnull URI source) {
		ChildSrcDirective childSrcDirective = this.getDirectiveByType(ChildSrcDirective.class);
		if (childSrcDirective == null) {
			return this.defaultsAllowSource(source);
		}
		return childSrcDirective.matchesSource(this.origin, source);
	}

	public boolean allowsChildFromSource(@Nonnull GUID source) {
		ChildSrcDirective childSrcDirective = this.getDirectiveByType(ChildSrcDirective.class);
		if (childSrcDirective == null) {
			return this.defaultsAllowSource(source);
		}
		return childSrcDirective.matchesSource(this.origin, source);
	}

	public boolean allowsWorkerFromSource(@Nonnull URI source) {
		WorkerSrcDirective workerSrcDirective = this.getDirectiveByType(WorkerSrcDirective.class);
		if (workerSrcDirective == null) {
			return this.allowsScriptFromSource(source);
		}
		return workerSrcDirective.matchesSource(this.origin, source);
	}

	public boolean allowsWorkerFromSource(@Nonnull GUID source) {
		WorkerSrcDirective workerSrcDirective = this.getDirectiveByType(WorkerSrcDirective.class);
		if (workerSrcDirective == null) {
			return this.allowsScriptFromSource(source);
		}
		return workerSrcDirective.matchesSource(this.origin, source);
	}

	public boolean allowsFrameFromSource(@Nonnull URI source) {
		FrameSrcDirective frameSrcDirective = this.getDirectiveByType(FrameSrcDirective.class);
		if (frameSrcDirective == null) {
			return this.allowsChildFromSource(source);
		}
		return frameSrcDirective.matchesSource(this.origin, source);
	}

	public boolean allowsFrameFromSource(@Nonnull GUID source) {
		FrameSrcDirective frameSrcDirective = this.getDirectiveByType(FrameSrcDirective.class);
		if (frameSrcDirective == null) {
			return this.allowsChildFromSource(source);
		}
		return frameSrcDirective.matchesSource(this.origin, source);
	}

	public boolean allowsFrameAncestor(@Nonnull URI source) {
		FrameAncestorsDirective frameAncestorsDirective = this.getDirectiveByType(FrameAncestorsDirective.class);
		if (frameAncestorsDirective == null) {
			return true;
		}
		return frameAncestorsDirective.matchesSource(this.origin, source);
	}

	public boolean allowsFrameAncestor(@Nonnull GUID source) {
		FrameAncestorsDirective frameAncestorsDirective = this.getDirectiveByType(FrameAncestorsDirective.class);
		if (frameAncestorsDirective == null) {
			return true;
		}
		return frameAncestorsDirective.matchesSource(this.origin, source);
	}

	public boolean allowsFontFromSource(@Nonnull URI source) {
		FontSrcDirective fontSrcDirective = this.getDirectiveByType(FontSrcDirective.class);
		if (fontSrcDirective == null) {
			return this.defaultsAllowSource(source);
		}
		return fontSrcDirective.matchesSource(this.origin, source);
	}

	public boolean allowsFontFromSource(@Nonnull GUID source) {
		FontSrcDirective fontSrcDirective = this.getDirectiveByType(FontSrcDirective.class);
		if (fontSrcDirective == null) {
			return this.defaultsAllowSource(source);
		}
		return fontSrcDirective.matchesSource(this.origin, source);
	}

	public boolean allowsObjectFromSource(@Nonnull URI source) {
		ObjectSrcDirective objectSrcDirective = this.getDirectiveByType(ObjectSrcDirective.class);
		if (objectSrcDirective == null) {
			return this.defaultsAllowSource(source);
		}
		return objectSrcDirective.matchesSource(this.origin, source);
	}

	public boolean allowsObjectFromSource(@Nonnull GUID source) {
		ObjectSrcDirective objectSrcDirective = this.getDirectiveByType(ObjectSrcDirective.class);
		if (objectSrcDirective == null) {
			return this.defaultsAllowSource(source);
		}
		return objectSrcDirective.matchesSource(this.origin, source);
	}

	public boolean allowsMediaFromSource(@Nonnull URI source) {
		MediaSrcDirective mediaSrcDirective = this.getDirectiveByType(MediaSrcDirective.class);
		if (mediaSrcDirective == null) {
			return this.defaultsAllowSource(source);
		}
		return mediaSrcDirective.matchesSource(this.origin, source);
	}

	public boolean allowsMediaFromSource(@Nonnull GUID source) {
		MediaSrcDirective mediaSrcDirective = this.getDirectiveByType(MediaSrcDirective.class);
		if (mediaSrcDirective == null) {
			return this.defaultsAllowSource(source);
		}
		return mediaSrcDirective.matchesSource(this.origin, source);
	}

	public boolean allowsManifestFromSource(@Nonnull URI source) {
		ManifestSrcDirective manifestSrcDirective = this.getDirectiveByType(ManifestSrcDirective.class);
		if (manifestSrcDirective == null) {
			return this.defaultsAllowSource(source);
		}
		return manifestSrcDirective.matchesSource(this.origin, source);
	}

	public boolean allowsManifestFromSource(@Nonnull GUID source) {
		ManifestSrcDirective manifestSrcDirective = this.getDirectiveByType(ManifestSrcDirective.class);
		if (manifestSrcDirective == null) {
			return this.defaultsAllowSource(source);
		}
		return manifestSrcDirective.matchesSource(this.origin, source);
	}

	public boolean allowsNavigation(@Nonnull URI destination) {
		NavigateToDirective navigateToDirective = this.getDirectiveByType(NavigateToDirective.class);
		if (navigateToDirective == null) {
			return true;
		}
		return navigateToDirective.matchesSource(origin, destination);
	}

	public boolean allowsNavigation(@Nonnull GUID destination) {
		NavigateToDirective navigateToDirective = this.getDirectiveByType(NavigateToDirective.class);
		if (navigateToDirective == null) {
			return true;
		}
		return navigateToDirective.matchesSource(origin, destination);
	}

	public boolean allowsFormAction(@Nonnull URI destination) {
		FormActionDirective formActionDirective = this.getDirectiveByType(FormActionDirective.class);
		if (formActionDirective == null) {
			return this.allowsNavigation(destination);
		}
		return formActionDirective.matchesSource(this.origin, destination);
	}

	public boolean allowsFormAction(@Nonnull GUID destination) {
		FormActionDirective formActionDirective = this.getDirectiveByType(FormActionDirective.class);
		if (formActionDirective == null) {
			return this.allowsNavigation(destination);
		}
		return formActionDirective.matchesSource(this.origin, destination);
	}

	public boolean hasSomeEffect() {
		for (Map.Entry<Class<?>, Directive<? extends DirectiveValue>> entry : this.directives.entrySet()) {
			Directive<? extends DirectiveValue> directive = entry.getValue();
			if (!(directive instanceof ReportToDirective) && !(directive instanceof ReportUriDirective)) {
				return true;
			}
		}
		return false;
	}

	private void insert(@Nonnull Directive x) {
		if (this.getDirectiveByType(x.getClass()) == null) {
			this.directives.put(x.getClass(), x);
		}
	}
}
