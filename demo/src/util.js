function escapeUsing(escaper) {
  return function(literalParts, ...interpolatedParts) {
    let s = literalParts[0];
    for (let [interpolatedPart, literalPart] of zip(interpolatedParts, literalParts.slice(1))) {
      s += escaper(interpolatedPart) + literalPart;
    }
    return s;
  }
}

function* zipWith(combine, ...generators) {
  generators = generators.map(g => g[Symbol.iterator]());
  do {
    let nexts = generators.map(g => g.next());
    if (nexts.some(n => n.done)) break;
    yield combine(...nexts.map(n => n.value));
  } while(true);
}

function* zip(...generators) {
  yield* zipWith(Array.of, ...generators);
}

function hex4(c) {
  let hex = c.charCodeAt(0).toString(16);
  return `${"0000".slice(hex.length)}${hex}`;
}

// TODO: also run appropriate minifiers
export const html = escapeUsing(s => s.replace(/[<>&"'`]/g, c => `&#x${hex4(c)};`))
export const js = escapeUsing(s => s.replace(/<\/script>/g, c => `\\u${hex4(c[0])}${c.slice(1)}`));

