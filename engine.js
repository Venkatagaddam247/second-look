/*
 * Second Look — detection engine
 * Runs entirely on-device (browser or Node). No network calls, no data leaves the device.
 *
 * analyze(text) returns:
 *   { score 0-100, level 'low'|'medium'|'high', category, findings[], links[], phones[], highlights[] }
 *
 * Every point of the score comes from a named, explainable finding.
 */
(function (root) {
  'use strict';

  // ---------------------------------------------------------------------------
  // 1. Known brands and their real domains (used for lookalike detection)
  // ---------------------------------------------------------------------------
  const BRANDS = {
    paypal: ['paypal.com', 'paypal.me'],
    amazon: ['amazon.com', 'amazon.ca', 'amazon.co.uk', 'amzn.to', 'a.co'],
    apple: ['apple.com', 'icloud.com'],
    icloud: ['icloud.com', 'apple.com'],
    microsoft: ['microsoft.com', 'live.com', 'outlook.com', 'office.com'],
    outlook: ['outlook.com', 'live.com', 'microsoft.com'],
    netflix: ['netflix.com'],
    google: ['google.com', 'gmail.com', 'youtube.com', 'goo.gl'],
    gmail: ['gmail.com', 'google.com'],
    facebook: ['facebook.com', 'fb.com', 'meta.com'],
    instagram: ['instagram.com'],
    whatsapp: ['whatsapp.com'],
    wellsfargo: ['wellsfargo.com'],
    chase: ['chase.com'],
    bankofamerica: ['bankofamerica.com', 'bofa.com'],
    citibank: ['citi.com', 'citibank.com'],
    capitalone: ['capitalone.com'],
    americanexpress: ['americanexpress.com'],
    usaa: ['usaa.com'],
    usps: ['usps.com'],
    fedex: ['fedex.com'],
    ups: ['ups.com'],
    dhl: ['dhl.com'],
    irs: ['irs.gov'],
    ssa: ['ssa.gov'],
    medicare: ['medicare.gov'],
    venmo: ['venmo.com'],
    zelle: ['zellepay.com'],
    cashapp: ['cash.app', 'squareup.com'],
    coinbase: ['coinbase.com'],
    walmart: ['walmart.com'],
    costco: ['costco.com'],
    ebay: ['ebay.com'],
    verizon: ['verizon.com'],
    tmobile: ['t-mobile.com'],
    xfinity: ['xfinity.com', 'comcast.com', 'comcast.net'],
    spectrum: ['spectrum.com', 'spectrum.net'],
    bestbuy: ['bestbuy.com'],
    geeksquad: ['bestbuy.com', 'geeksquad.com'],
    norton: ['norton.com'],
    mcafee: ['mcafee.com'],
    docusign: ['docusign.com', 'docusign.net'],
    dropbox: ['dropbox.com'],
    linkedin: ['linkedin.com'],
    ezpass: ['e-zpassiag.com', 'ezpassny.com', 'ezpassnj.com', 'ezpassva.com'],
    steam: ['steampowered.com', 'steamcommunity.com'],
    roblox: ['roblox.com'],
    fidelity: ['fidelity.com'],
    binance: ['binance.com'],
    // Short brand names: exact-skeleton matching only (too short for edit distance)
    att: ['att.com'],
    citi: ['citi.com', 'citibank.com']
  };
  const BRAND_NAMES = {
    paypal: 'PayPal', icloud: 'iCloud', wellsfargo: 'Wells Fargo', bankofamerica: 'Bank of America', citibank: 'Citibank',
    capitalone: 'Capital One', americanexpress: 'American Express', usaa: 'USAA', usps: 'USPS', fedex: 'FedEx', ups: 'UPS',
    dhl: 'DHL', irs: 'IRS', ssa: 'Social Security', cashapp: 'Cash App', tmobile: 'T-Mobile', bestbuy: 'Best Buy',
    geeksquad: 'Geek Squad', docusign: 'DocuSign', linkedin: 'LinkedIn', ezpass: 'E-ZPass', att: 'AT&T', ebay: 'eBay', whatsapp: 'WhatsApp'
  };
  const brandName = b => BRAND_NAMES[b] || b.charAt(0).toUpperCase() + b.slice(1);

  const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'rb.gy', 'cutt.ly', 'ow.ly',
    'shorturl.at', 'tiny.cc', 'rebrand.ly', 'buff.ly', 'v.gd', 'qrco.de', 's.id', 't.ly', 'shorte.st']);

  const RISKY_TLDS = new Set(['zip', 'mov', 'top', 'xyz', 'click', 'icu', 'buzz', 'rest', 'cfd', 'sbs',
    'lol', 'cyou', 'monster', 'gq', 'tk', 'ml', 'cf', 'ga', 'work', 'support', 'live', 'fun', 'quest', 'bond', 'vip', 'win']);

  const MULTI_PART_SUFFIXES = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'co.nz',
    'co.in', 'co.jp', 'com.br', 'com.mx', 'co.za', 'com.cn', 'com.sg', 'gc.ca']);

  // Characters scammers swap in because they look like Latin letters (Cyrillic, Greek, etc.)
  const CONFUSABLES = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'і': 'i', 'ј': 'j', 'ѕ': 's',
    'ԁ': 'd', 'һ': 'h', 'ӏ': 'l', 'ո': 'n', 'ս': 'u', 'ɑ': 'a', 'ο': 'o', 'ν': 'v', 'τ': 't', 'ι': 'i',
    'κ': 'k', 'ρ': 'p', 'α': 'a', 'ε': 'e', 'ℓ': 'l', 'ı': 'i', 'ⅰ': 'i', 'ｏ': 'o', 'ｅ': 'e', 'ａ': 'a'
  };

  // ---------------------------------------------------------------------------
  // 2. Text signals. Each has a weight, a scam category, and a plain-language reason.
  // ---------------------------------------------------------------------------
  const SIGNALS = [
    // Payment methods that real organizations never ask for
    { id: 'giftcard', w: 45, cat: 'payment', floor: 75,
      re: /\b(gift ?cards?|itunes cards?|apple cards?|google ?play cards?|steam cards?|ebay cards?|target cards?|vanilla (visa|card))\b/gi,
      title: 'Asks for payment with gift cards',
      why: 'No real company, bank, or government agency asks you to pay with gift cards. This is the #1 sign of a scam.' },
    { id: 'crypto_atm', w: 40, cat: 'payment', floor: 70,
      re: /\b(bitcoin (atm|machine|kiosk)|crypto(currency)? (atm|kiosk)|qr code.{0,30}(deposit|bitcoin|machine))\b/gi,
      title: 'Asks you to use a Bitcoin ATM',
      why: 'Government agencies and banks never ask you to deposit cash into a Bitcoin ATM to "protect" your money.' },
    { id: 'crypto', w: 22, cat: 'investment',
      re: /\b(bitcoin|btc|usdt|tether|ethereum|crypto(currency)?|wallet address)\b/gi,
      title: 'Mentions cryptocurrency',
      why: 'Crypto payments are hard to trace and almost impossible to get back, which is why scammers prefer them.' },
    { id: 'wire', w: 22, cat: 'payment',
      re: /\b(wire (the )?(money|funds|transfer)|western union|moneygram|(send|pay|transfer)\b[^.\n]{0,25}\b(via|with|through|by|on|using) (zelle|cash ?app|venmo|wire))\b/gi,
      title: 'Asks for a wire, Zelle, Cash App or Venmo payment',
      why: 'These payments work like cash. Once sent, they usually cannot be reversed.' },
    { id: 'courier', w: 40, cat: 'gov', floor: 70,
      re: /\b(courier|agent|officer) (will|would) (come|pick up|collect)|(gold|cash) (bars?|pickup)|withdraw (the |your )?cash and\b/gi,
      title: 'Wants someone to pick up cash or gold',
      why: 'Real agencies never send a courier to collect cash or gold from your home.' },

    // Credential / identity harvesting
    { id: 'otp_share', w: 40, cat: 'account', floor: 65,
      re: /\b((read|give|send|tell|share|provide|forward)( me| us)? (the |that |your )?(\d-digit )?(code|verification code|one[- ]time (code|password)|otp|pin))\b/gi,
      title: 'Asks you to share a security code',
      why: 'Codes sent to your phone are like keys to your account. Anyone who asks you to read one back is trying to break in.' },
    { id: 'ssn', w: 30, cat: 'account',
      re: /\b(social security (number|no\.?)|ssn|bank account number|routing number|card number|cvv|mother'?s maiden name|date of birth)\b/gi,
      title: 'Asks for sensitive personal information',
      why: 'Legitimate organizations do not ask for your Social Security number, card number, or account number by text or email.' },
    { id: 'verify', w: 18, cat: 'account',
      re: /\b(verify|confirm|validate|update|re-?activate|unlock|restore) (your |the )?(account|identity|information|details|login|payment (info|information|method)|billing)\b/gi,
      title: 'Asks you to "verify" or "update" your account',
      why: 'Scammers send fake "verify your account" messages to steal passwords. Go to the company\'s website or app yourself instead.' },
    { id: 'password', w: 18, cat: 'account',
      re: /\b(enter|provide|confirm|send) (your )?(password|passcode|login credentials|username and password)\b/gi,
      title: 'Asks for your password',
      why: 'No legitimate company will ever ask you to send your password.' },

    // Pressure tactics
    { id: 'urgency', w: 14, cat: null,
      re: /\b(immediately|urgent(ly)?|act now|right away|as soon as possible|asap|within (24|48|12|2) ?(hours|hrs|h)\b|final (notice|warning|reminder)|last (chance|warning|notice)|expires? (today|tonight|soon)|today only|time[- ]sensitive)\b/gi,
      title: 'Creates a sense of urgency',
      why: 'Scammers rush you so you don\'t have time to think or ask someone. Real problems can wait for you to check.' },
    { id: 'threat', w: 22, cat: 'gov',
      re: /\b(arrest(ed)?|warrant|lawsuit|legal action|deport(ed|ation)?|jail|prison|suspended (your )?social security|penalt(y|ies)|seized|frozen|criminal charges?)\b/gi,
      title: 'Threatens arrest, lawsuits, or penalties',
      why: 'Government agencies do not threaten you by text, email, or phone call. Threats are used to scare you into acting fast.' },
    { id: 'secrecy', w: 28, cat: null,
      re: /\b(don'?t|do not|never) (tell|discuss|mention|inform|share this with|talk to) (anyone|anybody|your (bank|family|kids|children|son|daughter)|the bank|bank (staff|employees|teller))|keep (this|it) (secret|confidential|between us)|don'?t hang up\b/gi,
      title: 'Tells you to keep it secret',
      why: 'Scammers isolate you so no one can warn you. Talking to someone you trust is always okay.' },
    { id: 'account_problem', w: 16, cat: 'account',
      re: /\b(unusual|suspicious|unauthori[sz]ed) (activity|sign[- ]?in|login|charge|transaction|purchase)|account (has been |is |will be )?(locked|suspended|limited|disabled|on hold|compromised|restricted|closed)\b/gi,
      title: 'Claims there is a problem with your account',
      why: 'Fake "problem with your account" alerts are the most common phishing trick. Check by opening the official app yourself.' },

    // Tech support
    { id: 'remote', w: 40, cat: 'tech', floor: 70,
      re: /\b(anydesk|teamviewer|ultraviewer|logmein|supremo|remote (access|desktop|control)|screen ?share|let (me|us|our technician) (access|connect to) your (computer|device|phone))\b/gi,
      title: 'Asks for remote access to your device',
      why: 'Letting a stranger control your computer gives them access to your bank accounts and files.' },
    { id: 'virus', w: 20, cat: 'tech',
      re: /\b(virus(es)?|malware|infected|trojan|spyware|been hacked|has been compromised|security alert|your (computer|device|pc) (is|has been) (locked|blocked))\b/gi,
      title: 'Says your device has a virus or was hacked',
      why: 'Pop-ups and messages claiming your computer is infected are almost always fake "tech support" scams.' },
    { id: 'renewal', w: 24, cat: 'tech',
      re: /\b((auto[- ]?)?renew(ed|al)? for \$|has (been )?(auto[- ]?)?renewed|about to (be )?renew(ed)?|if you (wish|want) to cancel|to cancel and (get|receive) a refund|(subscription|membership) (has been |will be )?(charged|renewed|billed))/gi,
      title: 'Claims you were charged for a renewal',
      why: 'Fake "your subscription renewed" messages want you to call them for a "refund", then they take over your computer or bank account.' },
    { id: 'storage', w: 20, cat: 'account',
      re: /\b(mailbox|storage|inbox) (is |has )?(almost |been )?full|password (is )?(expir(es|ing|ed))|(email|mailbox|photos|files) will be (deleted|deactivated|closed|disabled)|(will be|is going to be) (disconnected|shut off|cut off)|license will be suspended\b/gi,
      title: 'Threatens to delete or shut off something',
      why: 'Messages saying your email, photos, or service will be cut off are a common way to scare you into clicking.' },
    { id: 'call_now', w: 12, cat: 'tech',
      re: /\b(call|contact|dial|phone)\b[^.\n]{0,40}?(\b(now|immediately|today|asap)\b|(\+?1[\s.-]?)?\(?\b[2-9]\d{2}\)?[\s.-]?\d{3}[\s.-]?\d{4})/gi,
      title: 'Pushes you to call a phone number',
      why: 'Scammers include their own phone number. Only call the number on the back of your card or on the official website.' },

    // Common scam stories
    { id: 'prize', w: 22, cat: 'prize',
      re: /\b(you('ve| have)? (won|been selected)|congratulations[,!]? you|winner|claim your (prize|reward|gift)|lottery|sweepstakes|jackpot|free (iphone|gift|vacation))\b/gi,
      title: 'Says you won a prize',
      why: 'You cannot win a contest you never entered. Real prizes never require you to pay a fee first.' },
    { id: 'fee', w: 18, cat: 'prize',
      re: /\b(processing|shipping|release|clearance|redelivery|handling|small|customs|activation) fee\b/gi,
      title: 'Asks you to pay a small fee',
      why: 'A small "fee" is how scammers get your card details. The fee is just the start.' },
    { id: 'package', w: 18, cat: 'delivery',
      re: /\b(package|parcel|shipment|delivery)\b.{0,60}\b(failed|on hold|could not be delivered|unable to (be )?deliver|returned|pending|held|incomplete address|update (your )?(address|details))\b/gi,
      title: 'Claims a package delivery problem',
      why: 'Fake delivery texts are extremely common. Track packages only with the tracking number from your actual order.' },
    { id: 'toll', w: 20, cat: 'delivery',
      re: /\b(unpaid toll|toll (balance|charges?|violation|notice)|outstanding (toll|balance)|e-?z ?pass|sunpass|fastrak)\b/gi,
      title: 'Claims you owe an unpaid toll',
      why: 'Unpaid-toll texts are a widespread scam. Toll agencies don\'t text links demanding payment.' },
    { id: 'refund', w: 16, cat: 'account',
      re: /\b(refund|overpaid|overpayment|sent (you )?too much|accidentally (sent|deposited|transferred)|send (the|it) back|reimburse)\b/gi,
      title: 'Mentions a refund or overpayment',
      why: 'The "we refunded too much, please send it back" story is a trick to get you to send real money.' },
    { id: 'family', w: 26, cat: 'family',
      re: /\b(grandma|grandpa|grandmother|grandfather|it'?s me|hi (mum|mom|dad)|this is your (son|daughter|grandson|granddaughter))\b.{0,120}\b(jail|bail|accident|hospital|lawyer|attorney|new (number|phone)|lost my phone|broke my phone|trouble|need money)\b|\b(new (number|phone)|lost my phone|broke my phone)\b/gi,
      title: 'Claims to be a family member in trouble',
      why: 'Scammers pretend to be a grandchild or child who needs money fast. Call the person on the number you already have.' },
    { id: 'investment', w: 26, cat: 'investment',
      re: /\b(guaranteed (returns?|profits?|income)|risk[- ]free (investment|returns?)|double your (money|investment)|trading (platform|signals?)|forex|(\d{2,4})% (returns?|profit|daily|weekly|monthly)|investment opportunity|mining pool|passive income)\b/gi,
      title: 'Promises guaranteed or huge returns',
      why: 'No real investment guarantees profit. Investment fraud is the most expensive scam reported to the FBI.' },
    { id: 'job', w: 16, cat: 'job',
      re: /\b(work from home|earn \$?\d[\d,]* (a|per) (day|hour|week)|no experience (needed|required)|part[- ]time (job|position|opportunity)|hiring now|recruiter from|like (videos|posts) and (get|earn) paid|task[- ]based)\b/gi,
      title: 'Offers easy money for little work',
      why: 'Fake job offers lead to "training fees" or ask you to deposit checks that later bounce.' },
    { id: 'chat_move', w: 12, cat: 'investment',
      re: /\b(telegram|whatsapp|signal app|text me on|add me on|message me on)\b/gi,
      title: 'Asks to move the conversation to another app',
      why: 'Scammers move you to encrypted apps where they are harder to report and block.' },
    { id: 'wrong_number', w: 10, cat: 'investment',
      re: /\b(sorry,? (wrong number|i think i have the wrong)|is this \w+\?|are you \w+\? (we|i) (met|talked))/gi,
      title: 'Starts like a "wrong number" text',
      why: 'Friendly "wrong number" texts are often the opening move of long romance or investment scams.' },
    { id: 'gov_impersonation', w: 12, cat: 'gov',
      re: /\b(irs|internal revenue service|social security administration|ssa|medicare|fbi|federal agent|us marshals?|homeland security|customs and border|department of justice|sheriff'?s office)\b/gi,
      title: 'Claims to be a government agency',
      why: 'Government agencies contact people by mail first. They don\'t demand payment by text, email, or phone.' },
    { id: 'generic_greeting', w: 8, cat: null,
      re: /\b(dear (customer|user|client|valued|member|account holder|sir|madam|beneficiary)|hello (customer|user))\b/gi,
      title: 'Uses a generic greeting',
      why: 'Companies you do business with usually know your name.' },
    { id: 'click_link', w: 8, cat: null,
      re: /\b(click (here|the link|below|this link)|tap (here|the link)|follow the link|log ?in (here|below|now))\b/gi,
      title: 'Pressures you to click a link',
      why: 'If something needs your attention, go to the official website or app yourself instead of clicking.' }
  ];

  // Signals that make a message look more like a legitimate notification
  const SAFE_SIGNALS = [
    { id: 'safe_otp', w: -30, re: /\b(do not|don'?t|never) share (this|the|your) code|we (will )?never (ask|call|text) (you )?(for|to)|(never|no one from \w+ will) ask (you )?for (this|your) code/gi,
      title: 'Warns you not to share the code', why: 'Real one-time code messages warn you never to share them. That is a good sign.' },
    { id: 'safe_ignore', w: -12, re: /\bif (you|this) (didn'?t|did not|wasn'?t|was not) (request|you|make)/gi,
      title: 'Tells you to ignore it if you didn\'t request it', why: 'Legitimate notices usually tell you no action is needed if you didn\'t ask for it.' }
  ];

  const CATEGORY_INFO = {
    payment: { name: 'Untraceable payment scam' },
    gov: { name: 'Government impersonation scam' },
    account: { name: 'Account phishing scam' },
    tech: { name: 'Tech support scam' },
    prize: { name: 'Prize / lottery scam' },
    delivery: { name: 'Fake delivery or toll scam' },
    family: { name: 'Family emergency ("grandparent") scam' },
    investment: { name: 'Investment / crypto scam' },
    job: { name: 'Fake job scam' },
    link: { name: 'Phishing link' }
  };

  // ---------------------------------------------------------------------------
  // 3. Helpers
  // ---------------------------------------------------------------------------
  function levenshtein(a, b) {
    if (a === b) return 0;
    const m = a.length, n = b.length;
    if (!m) return n; if (!n) return m;
    let prev = new Array(n + 1), cur = new Array(n + 1);
    for (let j = 0; j <= n; j++) prev[j] = j;
    for (let i = 1; i <= m; i++) {
      cur[0] = i;
      for (let j = 1; j <= n; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
        // transposition (Damerau): "pyapal" vs "paypal"
        if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) cur[j] = Math.min(cur[j], prev[j - 1]);
      }
      [prev, cur] = [cur, prev];
    }
    return prev[n];
  }

  // Punycode decoder (RFC 3492) so xn-- domains can be shown as the characters they really use
  function punyDecode(input) {
    const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
    const out = [];
    let i = 0, n = 128, bias = 72;
    let basic = input.lastIndexOf('-');
    if (basic < 0) basic = 0;
    for (let j = 0; j < basic; j++) out.push(input.charCodeAt(j));
    const digit = c => c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base;
    const adapt = (delta, num, first) => {
      let k = 0; delta = first ? Math.floor(delta / damp) : delta >> 1; delta += Math.floor(delta / num);
      for (; delta > ((base - tMin) * tMax) >> 1; k += base) delta = Math.floor(delta / (base - tMin));
      return Math.floor(k + (base - tMin + 1) * delta / (delta + skew));
    };
    for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
      const oldi = i;
      for (let w = 1, k = base; ; k += base) {
        if (idx >= input.length) return null;
        const d = digit(input.charCodeAt(idx++));
        if (d >= base) return null;
        i += d * w;
        const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (d < t) break;
        w *= base - t;
      }
      bias = adapt(i - oldi, out.length + 1, oldi === 0);
      n += Math.floor(i / (out.length + 1));
      i %= out.length + 1;
      out.splice(i++, 0, n);
    }
    return String.fromCodePoint(...out);
  }

  function toUnicodeHost(host) {
    return host.split('.').map(l => l.startsWith('xn--') ? (punyDecode(l.slice(4)) || l) : l).join('.');
  }

  // Reduce a label to what it *looks like*: Cyrillic "а" -> "a", "0" -> "o", "rn" -> "m", etc.
  function skeleton(s) {
    let out = '';
    for (const ch of s.toLowerCase()) out += CONFUSABLES[ch] || ch;
    return out.replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/5/g, 's').replace(/4/g, 'a')
      .replace(/\$/g, 's').replace(/@/g, 'a').replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/-/g, '').replace(/i/g, 'l');
  }

  function registrableDomain(host) {
    const parts = host.split('.');
    if (parts.length <= 2) return host;
    const last2 = parts.slice(-2).join('.');
    if (MULTI_PART_SUFFIXES.has(last2)) return parts.slice(-3).join('.');
    return last2;
  }

  function isOfficial(host, domains) {
    return domains.some(d => host === d || host.endsWith('.' + d));
  }

  // ---------------------------------------------------------------------------
  // 4. Link analysis
  // ---------------------------------------------------------------------------
  const URL_RE = /\b((?:https?:\/\/|www\.)[^\s<>"'()]+|(?:[a-z0-9¡-￿](?:[a-z0-9¡-￿-]{0,61}[a-z0-9¡-￿])?\.)+(?:com|net|org|info|biz|us|co|io|me|app|gov|edu|ca|uk|xyz|top|click|icu|buzz|zip|mov|live|shop|site|online|cfd|sbs|lol|vip|win|support|work|tk|ml|cf|gq|ga|ly|gl|at|to|id|de)(?:\/[^\s<>"']*)?)/giu;

  function analyzeLink(raw) {
    const findings = [];
    let cleaned = raw.replace(/[.,;:!?)\]]+$/, '');
    let urlText = /^https?:\/\//i.test(cleaned) ? cleaned : 'http://' + cleaned;
    let u;
    try { u = new URL(urlText); } catch (e) { return null; }
    const host = u.hostname.toLowerCase().replace(/\.$/, '');
    const displayHost = toUnicodeHost(host);
    const reg = registrableDomain(host);
    const regLabel = reg.split('.')[0];
    const tld = host.split('.').pop();
    const add = (w, title, why, floor) => findings.push({ w, title, why, floor: floor || 0 });

    // Raw text may have had a username part like "paypal.com@evil.net"
    if (/^[a-z]+:\/\/[^/]*@/i.test(urlText) || u.username) {
      add(40, 'Link hides its real destination with "@"', 'Everything before the "@" is ignored by your browser. The real site is ' + displayHost + '.', 70);
    }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[')) {
      add(30, 'Link goes to a bare number address', 'Real companies use names like amazon.com, not a string of numbers.', 60);
    }
    const hasUnicode = host.includes('xn--') || /[^\x00-\x7f]/.test(raw.split('/')[2] || raw);
    if (hasUnicode) {
      add(35, 'Link uses look-alike foreign letters', 'This address uses characters from another alphabet that look like normal letters: ' + displayHost, 65);
    }
    if (SHORTENERS.has(host)) {
      add(14, 'Link is shortened', 'Short links (like ' + host + ') hide where they really go.');
    }
    if (RISKY_TLDS.has(tld)) {
      add(16, 'Unusual website ending (.' + tld + ')', 'Endings like .' + tld + ' are cheap to register and are very common in scam links.');
    }
    if (u.protocol === 'http:' && /^http:\/\//i.test(cleaned)) {
      add(6, 'Link is not secure (http)', 'The link doesn\'t use a secure connection.');
    }
    if (host.split('.').length >= 5) {
      add(8, 'Very long web address', 'Long chains of words before the real domain are used to look official.');
    }

    // Brand impersonation
    const labels = host.split('.');
    const regSkel = skeleton(toUnicodeHost(regLabel));
    let impersonated = null;
    const officialSomewhere = Object.values(BRANDS).some(d => isOfficial(host, d));
    const tokens = toUnicodeHost(regLabel).split('-').map(skeleton).filter(Boolean);
    const sub = labels.slice(0, -reg.split('.').length);
    for (const brand in BRANDS) {
      if (officialSomewhere) break;
      const domains = BRANDS[brand];
      const bSkel = skeleton(brand);
      // a) whole domain name looks like the brand (paypa1.com, аpple.com, arnazon.com)
      if (regSkel === bSkel) { impersonated = { brand, how: 'is a look-alike of' }; break; }
      // b) one or two typos away (paypall.com, amazom.com). Short names are skipped to avoid false alarms.
      if (brand.length >= 6) {
        const d = levenshtein(regSkel, bSkel);
        if (d > 0 && d <= (brand.length >= 9 ? 2 : 1)) { impersonated = { brand, how: 'is a misspelling of' }; break; }
      }
      // c) brand name stuffed into a different domain (paypal-secure-login.com, usps-redelivery.top)
      if (tokens.length > 1 || brand.length >= 6) {
        const hit = tokens.some(t => t === bSkel || (bSkel.length >= 6 && t !== bSkel && (t.startsWith(bSkel) || t.endsWith(bSkel))));
        if (hit && regSkel !== bSkel) { impersonated = { brand, how: 'borrows the name of' }; break; }
      }
      // d) brand used as a subdomain (paypal.com.account-check.net, usps.parcel-help.top)
      if (sub.some(l => skeleton(l) === bSkel) || sub.join('.').includes(domains[0])) {
        impersonated = { brand, how: 'puts this name in front of', sub: true }; break;
      }
    }
    if (impersonated) {
      const real = BRANDS[impersonated.brand][0];
      const pretty = brandName(impersonated.brand);
      const why = impersonated.sub
        ? 'The real website here is ' + reg + ', not ' + real + '. Scammers put "' + impersonated.brand + '" at the front to fool you.'
        : displayHost + ' ' + impersonated.how + ' ' + pretty + ' (' + real + '), but it is NOT ' + pretty + '\'s real website.';
      add(45, 'Fake ' + pretty + ' website', why, 80);
    }

    const total = findings.reduce((s, f) => s + f.w, 0);
    return {
      raw: cleaned,
      host: displayHost,
      realSite: toUnicodeHost(reg),
      verdict: total >= 35 ? 'danger' : total >= 12 ? 'caution' : 'ok',
      impersonates: impersonated ? BRANDS[impersonated.brand][0] : null,
      findings
    };
  }

  // ---------------------------------------------------------------------------
  // 5. Main analysis
  // ---------------------------------------------------------------------------
  function analyze(text) {
    text = String(text || '');
    const findings = [];
    const highlights = [];
    const catScore = {};
    let floor = 0;

    for (const s of SIGNALS) {
      s.re.lastIndex = 0;
      let m;
      const distinct = new Set();
      while ((m = s.re.exec(text)) !== null) {
        if (m[0].length === 0) { s.re.lastIndex++; continue; }
        distinct.add(m[0].toLowerCase());
        highlights.push({ start: m.index, end: m.index + m[0].length, id: s.id, sev: s.w >= 25 ? 'high' : 'med' });
      }
      if (distinct.size) {
        // More separate pieces of evidence for the same signal = a bit more weight (capped)
        const w = Math.round(s.w * Math.min(1 + 0.3 * (distinct.size - 1), 1.6));
        findings.push({ id: s.id, w, title: s.title, why: s.why, kind: 'text' });
        if (s.cat) catScore[s.cat] = (catScore[s.cat] || 0) + w;
        if (s.floor) floor = Math.max(floor, s.floor);
      }
    }

    // "Security code" alone in a normal 2FA text is fine; mitigate when safe wording appears
    for (const s of SAFE_SIGNALS) {
      s.re.lastIndex = 0;
      if (s.re.test(text)) findings.push({ id: s.id, w: s.w, title: s.title, why: s.why, kind: 'safe' });
    }

    // Links
    const links = [];
    const seen = new Set();
    URL_RE.lastIndex = 0;
    let lm;
    while ((lm = URL_RE.exec(text)) !== null) {
      // Skip sentence fragments like "phone.To" (bare domains are written in lowercase)
      if (!/^(https?:\/\/|www\.)/i.test(lm[0]) && /[A-Z]/.test(lm[0].split('/')[0])) continue;
      const res = analyzeLink(lm[0]);
      if (!res || seen.has(res.raw)) continue;
      seen.add(res.raw);
      links.push(res);
      if (res.verdict !== 'ok') highlights.push({ start: lm.index, end: lm.index + lm[0].length, id: 'link', sev: res.verdict === 'danger' ? 'high' : 'med' });
    }
    // Score the single worst link (plus a little for each extra risky one)
    const linkTotals = links.map(l => l.findings.reduce((s, f) => s + f.w, 0)).sort((a, b) => b - a);
    if (linkTotals.length && linkTotals[0] > 0) {
      const worst = links.find(l => l.findings.reduce((s, f) => s + f.w, 0) === linkTotals[0]);
      const lw = linkTotals[0] + linkTotals.slice(1).reduce((s, x) => s + x * 0.25, 0);
      findings.push({ id: 'links', w: Math.round(lw), title: worst.verdict === 'danger' ? 'Dangerous link' : 'Suspicious link',
        why: worst.findings.map(f => f.why).join(' '), kind: 'link' });
      catScore.link = (catScore.link || 0) + lw;
      for (const f of worst.findings) floor = Math.max(floor, f.floor || 0);
    }

    // Phone numbers (shown so the person knows not to call them)
    const phones = [];
    const PHONE_RE = /(?:\+?1[\s.-]?)?\(?\b[2-9]\d{2}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g;
    let pm;
    while ((pm = PHONE_RE.exec(text)) !== null) if (!phones.includes(pm[0].trim())) phones.push(pm[0].trim());

    // Shouting
    const letters = text.replace(/[^A-Za-z]/g, '');
    const caps = text.replace(/[^A-Z]/g, '').length;
    if (letters.length > 40 && caps / letters.length > 0.45) {
      findings.push({ id: 'caps', w: 6, title: 'Lots of CAPITAL LETTERS', why: 'Shouting is a pressure tactic.', kind: 'text' });
    }

    // Combination bonuses: classic scam recipes are more than the sum of their parts
    const has = id => findings.some(f => f.id === id);
    const combos = [];
    if (has('threat') && (has('gov_impersonation')) && (has('giftcard') || has('wire') || has('crypto') || has('crypto_atm') || has('call_now')))
      combos.push(['Classic government-impersonation pattern', 'An "official" threat plus a demand to pay or call right away is how impersonation scams work.', 20]);
    if ((has('account_problem') || has('verify')) && (has('urgency')) && links.some(l => l.verdict !== 'ok'))
      combos.push(['Classic phishing pattern', 'An "account problem" + a deadline + a link is the textbook phishing recipe.', 18]);
    if (has('virus') && (has('call_now') || has('remote')))
      combos.push(['Classic tech-support scam pattern', 'A virus warning that tells you to call a number is a well-known scam.', 20]);
    if ((has('package') || has('toll')) && links.some(l => l.verdict !== 'ok'))
      { combos.push(['Classic delivery/toll text pattern', 'A delivery or toll problem with a strange link is one of the most common scam texts.', 15]); catScore.delivery = (catScore.delivery || 0) + 15; }
    const unexpectedCharge = has('renewal') || has('refund') || has('account_problem') || /\b(did not|didn'?t) (make|authori[sz]e|place|request) (this|the)/i.test(text) || /\b(charged|order of|purchase of) \$\d/i.test(text);
    if (unexpectedCharge && phones.length && has('call_now'))
      combos.push(['"Call us about this charge" pattern', 'Scammers send fake charge or renewal alerts with their own phone number. When you call, they ask for remote access or bank details. Real alerts tell you to use the number on your card or in the official app.', 24]);
    if (has('refund') && has('wire'))
      combos.push(['Overpayment pattern', '"I sent you money by mistake, please send it back" is a trick. The original payment is usually fake or stolen and will disappear.', 24]);
    if (has('family') && /\b(money|\$\d|pay|bill|bail|transfer|send)\b/i.test(text))
      combos.push(['Family emergency money request', 'A "family member" with a new number asking for money is a very common scam. Call them on their old number first.', 22]);
    if (has('job') && (has('chat_move') || has('fee')))
      combos.push(['Fake job pattern', 'Real employers don\'t recruit through Telegram or WhatsApp with promises of easy daily pay.', 18]);
    if (has('ssn') && /\b(reply|respond|text|provide|send|confirm|enter)\b/i.test(text))
      combos.push(['Asks for private details by message', 'Asking you to send your Social Security, card, or account number by text or email is always a red flag.', 20]);
    if (has('storage') && (links.some(l => l.verdict !== 'ok') || has('click_link') || has('urgency')))
      combos.push(['"Act now or lose access" pattern', 'A warning that something will be shut off, plus a link or deadline, is designed to make you click before you think.', 16]);
    if (has('virus') && phones.length && !has('call_now'))
      combos.push(['Classic tech-support scam pattern', 'A virus warning with a phone number is a well-known scam. Microsoft and Apple don\'t put phone numbers in warnings.', 20]);
    for (const [title, why, w] of combos) findings.push({ id: 'combo', w, title, why, kind: 'combo' });

    // Score: diminishing returns so many small hints don't max out, but a few strong ones do
    const raw = findings.reduce((s, f) => s + f.w, 0);
    let score = raw <= 0 ? 0 : Math.round(100 * (1 - Math.exp(-raw / 55)));
    const hasSafe = findings.some(f => f.kind === 'safe');
    if (!hasSafe || floor >= 75) score = Math.max(score, floor);
    score = Math.min(99, Math.max(0, score));
    const level = score >= 60 ? 'high' : score >= 30 ? 'medium' : 'low';

    // Prefer the story the message tells (toll, bank, family...) over "phishing link"
    let category = null, best = 0;
    for (const c in catScore) if (c !== 'link' && catScore[c] > best) { best = catScore[c]; category = c; }
    if (!category || best < 15) category = catScore.link ? 'link' : category;
    if (level === 'low') category = null;

    findings.sort((a, b) => b.w - a.w);
    return {
      score, level,
      category,
      categoryName: category ? CATEGORY_INFO[category].name : null,
      findings,
      links,
      phones,
      highlights: mergeHighlights(highlights)
    };
  }

  function mergeHighlights(h) {
    h.sort((a, b) => a.start - b.start || b.end - a.end);
    const out = [];
    for (const x of h) {
      const last = out[out.length - 1];
      if (last && x.start < last.end) {
        last.end = Math.max(last.end, x.end);
        if (x.sev === 'high') last.sev = 'high';
      } else out.push(Object.assign({}, x));
    }
    return out;
  }

  // ---------------------------------------------------------------------------
  // 6. What to do next — tailored to the kind of scam
  // ---------------------------------------------------------------------------
  const ADVICE = {
    common: [
      'Don\'t reply, click links, or call any number in the message.',
      'If you\'re worried it might be real, contact the company yourself using the official app, website, or the number on the back of your card.'
    ],
    payment: ['Never pay anyone with gift cards, crypto, or wire transfers because they asked you to. If you already bought gift cards, keep the cards and receipts and call the card company\'s number on the back right away.'],
    gov: ['Hang up or delete it. The IRS, Social Security, and police do not call or text to demand payment or threaten arrest. If unsure, call the agency at the number on its official .gov website.'],
    account: ['Open the company\'s official app or type its website yourself to check your account. Never type a code or password into a page you reached from a message.'],
    tech: ['Close the pop-up or hang up. Don\'t let anyone remote into your computer. If you already did, disconnect from the internet and have a trusted person or a local repair shop check your device.'],
    prize: ['Ignore it. Real prizes never ask you to pay a fee or give bank details to collect.'],
    delivery: ['Track packages only from the store\'s order page or the carrier\'s official app. Check tolls by logging into your toll account directly.'],
    family: ['Hang up and call your family member at the number you already have for them, or ask a question only they would know. Agree on a family "safe word" for emergencies.'],
    investment: ['Stop sending money and don\'t try to "unlock" withdrawals by paying fees or taxes. If you met this person online and never in person, talk to someone you trust before doing anything else.'],
    job: ['Real employers don\'t ask you to pay for training or equipment, or to deposit a check and send part of it back.'],
    link: ['Don\'t open the link. If you already entered a password on it, change that password now (and anywhere you reused it) and turn on two-step verification.']
  };
  const IF_PAID = [
    'Call your bank or card company right away using the number on the back of your card. Ask them to stop or reverse the payment.',
    'Report it to the FTC at ReportFraud.ftc.gov and to the FBI at IC3.gov.',
    'Forward scam texts to 7726 (SPAM) and phishing emails to reportphishing@apwg.org.',
    'Free, judgment-free help: AARP Fraud Watch Network Helpline, 877-908-3360 (Mon–Fri, 8am–8pm ET).'
  ];

  function advice(result) {
    const steps = [];
    if (result.category && ADVICE[result.category]) steps.push(...ADVICE[result.category]);
    steps.push(...ADVICE.common);
    return { steps, ifPaid: IF_PAID };
  }

  const api = { analyze, analyzeLink, advice, skeleton, levenshtein, punyDecode, toUnicodeHost, registrableDomain, BRANDS, CATEGORY_INFO };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.SecondLook = api;
})(typeof window !== 'undefined' ? window : globalThis);
