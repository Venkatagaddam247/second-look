// Run with:  node tests/run.js
// Checks the engine against a hand-labeled set of scam and legitimate messages,
// plus unit tests for the look-alike link detector.
const path = require('path');
const SL = require(path.join(__dirname, '..', 'engine.js'));
const corpus = require('./corpus.json');

let failures = 0;
const check = (cond, msg) => { if (!cond) { failures++; console.log('  FAIL ' + msg); } };

// --- 1. Link unit tests -----------------------------------------------------
console.log('Link detector');
const linkCases = [
  ['https://paypa1.com/login', 'danger'],
  ['http://paypal.com.security-check.net', 'danger'],
  ['arnazon.com', 'danger'],
  ['https://xn--pple-43d.com', 'danger'],       // Cyrillic "а" + "pple"
  ['usps-redelivery.top', 'danger'],
  ['https://www.paypal.com/signin', 'ok'],
  ['https://mail.google.com', 'ok'],
  ['amazon.co.uk', 'ok'],
  ['sinclair.edu', 'ok'],
  ['purchase.com', 'ok'],                       // contains "chase" but is not impersonating it
  ['stream.com', 'ok'],                          // one letter from "steam", short names are not typo-checked
  ['bit.ly/abc', 'caution'],
  ['http://192.168.4.20/login', 'danger'],
  ['https://paypal.com@evil.example.net', 'danger']
];
for (const [url, expected] of linkCases) {
  const r = SL.analyzeLink(url);
  const ok = r && r.verdict === expected;
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${url.padEnd(40)} -> ${r ? r.verdict : 'null'}${r && r.impersonates ? ' (pretends to be ' + r.impersonates + ')' : ''}`);
  if (!ok) failures++;
}
check(SL.punyDecode('pple-43d') === 'аpple', 'punycode decode');

// --- 2. Message sets ----------------------------------------------------------
// corpus.json  = messages used while building and tuning the rules
// holdout.json = messages written BEFORE the last round of tuning and never tuned on.
//                This is the honest measure of how well it generalizes.
function evaluate(name, set) {
  console.log(`\n${name} (scam = score >= 60, "Very likely a scam")`);
  let tp = 0, fp = 0, tn = 0, fn = 0, medLegit = 0, medScam = 0;
  for (const item of set) {
    const r = SL.analyze(item.text);
    const flagged = r.level === 'high';
    if (item.label === 'scam') {
      flagged ? tp++ : fn++;
      if (!flagged) { if (r.level === 'medium') medScam++; console.log(`  missed, scored ${r.level} (${r.score}): ${item.text.slice(0, 70)}...`); }
    } else {
      flagged ? fp++ : tn++;
      if (r.level === 'medium') medLegit++;
      if (r.level !== 'low') console.log(`  legit scored ${r.level} (${r.score}): ${item.text.slice(0, 70)}  [${r.findings.map(f => f.id).join(',')}]`);
    }
  }
  console.log(`  Scams flagged "very likely":      ${tp}/${tp + fn}  (${(100 * tp / (tp + fn)).toFixed(0)}%)`);
  console.log(`  Scams flagged at least "careful":  ${tp + medScam}/${tp + fn}`);
  console.log(`  Legit wrongly called "very likely": ${fp}/${fp + tn}`);
  console.log(`  Legit marked "be careful":          ${medLegit}/${fp + tn}`);
  return { tp, fp, tn, fn };
}
evaluate('Development set', corpus);
evaluate('Held-out set', require('./holdout.json'));

console.log(failures === 0 ? '\nAll link unit tests passed.' : `\n${failures} test(s) failed.`);
process.exitCode = failures ? 1 : 0;
