salvation
==========

This is a general purpose library for working with Content Security Policy policies.

* parse CSP policies into an easy-to-use representation
* ask questions about what a CSP policy allows or restricts
* warn about nonsensical CSP policies and deprecated or nonstandard features
* safely create, manipulate, and merge CSP policies
* render and optimise CSP policies

### Install

```sh
mvn install
```

### Create a Policy

Parse a policy using one of the `Parser.parse` static methods. An `Origin` or `String` may be given as the origin. The third parameter, if given, will be populated with notices.

```java
List<Warning> notices = new ArrayList();
Origin origin = URI.parse("http://example.com");
String policyText = "...";
Policy p = Parser.parse(policyText, origin, notices);
```

To include location information, use `ParserWithLocation.parse` in place of `Parser.parse`.

A policy may also be created using the `Policy` constructor and populated using the `addDirective` method.

```java
Origin origin = URI.parse("http://example.com");
Policy p = new Policy(origin);
Set<SourceExpression> scriptSourceValues = new HashSet<>();
scriptSourceValues.add(new None());
p.addDirective(new ScriptSrcDirective(scriptSourceValues));
```

### Query a Policy

```java
Policy p = Parser.parse("script-src a; default-src b", "http://example.com");
p.allowsScriptFromSource(Uri.parse("a")); // true
p.allowsScriptFromSource(Uri.parse("b")); // false
p.allowsStyleFromSource(Uri.parse("b")); // true
```
