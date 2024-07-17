salvation
==========

This is a general purpose library for working with Content Security Policy policies.

* parse CSP policies into an easy-to-use representation
* ask questions about what a CSP policy allows or restricts
* warn about nonsensical CSP policies and deprecated or nonstandard features
* safely create and manipulate CSP policies
* render CSP policies

[cspvalidator.org](https://cspvalidator.org) demonstrates some of the features of Salvation in action.

### Install

```sh
mvn install
```

### A Note on CSP

The CSP specification is fairly complex even if you only care about the latest version. However, in practice you are likely to care that your policy does the things you intend it to on the browsers you care about, which are likely to implement different and potentially broken subsets of the specification (and potentially additional behavior which is not in the specification). And there are inevitable tradeoffs to be made regarding the size of your policy vs the security it provides.

As such, this project does not attempt to provide a one-size-fits-all way to manipulate a policy purely in terms of its effects - the full set of effects across all browsers is too vast to provide an effective API in general. It can help you build up a policy based on the directives and source-expressions you want, but to ensure your policy is correct, for your own definition of correct, there is no alternative to testing it on the real browsers you care about.


### Create a Policy

Parse a policy using either `Policy.parseSerializedCSP` or `Policy.parseSerializedCSPList`. The second parameter will be called for each warning or error.

```java
String policyText = "script-src 'none'";
Policy policy = Policy.parseSerializedCSP(policyText, (severity, message, directiveIndex, valueIndex) -> {
  System.err.println(severity.name() + " at directive " + directiveIndex + (valueIndex == -1 ? "" : " at value " + valueIndex) + ": " + message);
});
```

### Query a Policy

The high-level querying methods allow you to specify whatever relevant information you have. The missing information will be assumed to be worst-case - that is, these methods will return `true` only if any object which matches the provided characteristics would be allowed, regardless of its other characteristics. 

```java
Policy policy = Policy.parseSerializedCSP("script-src http://a", Policy.PolicyErrorConsumer.ignored);

// true
System.out.println(policy.allowsExternalScript(
  Optional.empty(),
  Optional.empty(),
  Optional.of(URI.parse("http://a")),
  Optional.empty(),
  Optional.empty()
));

// false
System.out.println(policy.allowsExternalScript(
  Optional.empty(),
  Optional.empty(),
  Optional.empty(),
  Optional.empty(),
  Optional.empty()
));
```

Note that these methods were correct according to current draft of the CSP specification when this library was written, but no browser implements precisely the current draft, and changes to the specification may also invalidate assumptions this library makes. There is no alternative to testing on the browsers you care about.

Because the `Policy` objects are rich structures, you can also ask about the presence or absence of specific directives or expressions:

```java
Policy policy = Policy.parseSerializedCSP("script-src 'strict-dynamic'", Policy.PolicyErrorConsumer.ignored);

// Assumes the policy has a `script-src` directive (or else the `get` would throw), and checks if it contains the `'strict-dynamic'` source expression
System.out.println(policy.getFetchDirective(FetchDirectiveKind.ScriptSrc).get().strictDynamic());
```

### Manipulate a Policy

```java
Policy policy = Policy.parseSerializedCSP("", Policy.PolicyErrorConsumer.ignored);

policy.add("sandbox", Collections.emptyList(), Directive.DirectiveErrorConsumer.ignored);

// you can use the provided Java APIs to manipulate values Salvation knows about
policy.sandbox().get().setAllowScripts(true);

// or you can use the lower-level APIs to manipulate values directly 
policy.sandbox().get().addValue("allow-something-new");

// "sandbox allow-scripts allow-something-new"
System.out.println(policy.toString());

```

### Serialize a Policy

```java
policy.toString();
```

## Transpiling to JavaScript
To reduce the overhead of running this library, it will now automatically be transpiled to JS as part of the compile goal by using [TeaVM](https://teavm.org/). It can then be placed on any webpage to be used as static JavaScript, thus alleviating the need for a JRE.

The transpiled code will be placed in `target/javascript` as `salvation-v${project.version}.min.js`.

If you experience errors relating to TeaVM transpiling, check the [supported TeaVM classes](https://teavm.org/jcl-report/recent/jcl.html).

### Using the JavaScript

First run `mvn clean install` to build the JS file. Then include `salvation-vX.X.X.min.js` in your webpage.
To use the parsing functions in on the webpage run `window.main()` to initialize them. From then on, `window.parseSerializedCSPList()` and `window.parseSerializedCSP()` will be available.

`parseSerializedCSP()` and `parseSerializedCSPList()` will return strings containing the parsing results. If there are multiple results, they will be separated by a newline. This is simply because TeaVM requires a lot of extra work for it to be able to return JS objects.
