// In-browser WCAG contrast audit for dev use. Load it on a page (for example by adding a script tag from
// the browser console), then call window.__audit(). It reports visible text below 4.5:1 (3:1 for large text).
// Text over images or gradients (hero, call-to-action band, footer) is skipped and must be checked by hand.
window.__audit = function () {
  function parse(c) { var m = c.match(/rgba?\(([^)]+)\)/); if (!m) return null; var p = m[1].split(',').map(parseFloat); return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 }; }
  function over(top, bot) {
    var a = top.a + bot.a * (1 - top.a); if (a === 0) return { r: 0, g: 0, b: 0, a: 0 };
    return { r: (top.r * top.a + bot.r * bot.a * (1 - top.a)) / a, g: (top.g * top.a + bot.g * bot.a * (1 - top.a)) / a, b: (top.b * top.a + bot.b * bot.a * (1 - top.a)) / a, a: a };
  }
  function bgOf(el) {
    var layers = [], e = el;
    while (e) {
      var cs = getComputedStyle(e), c = parse(cs.backgroundColor);
      if (c && c.a > 0) layers.push(c);
      if (cs.backgroundImage && cs.backgroundImage !== 'none' && e !== document.body && e !== document.documentElement) layers.push({ skip: true });
      e = e.parentElement;
    }
    var base = { r: 11, g: 20, b: 38, a: 1 };
    for (var i = layers.length - 1; i >= 0; i--) { if (layers[i].skip) return null; base = over(layers[i], base); }
    return base;
  }
  function lum(c) { function f(v) { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); } return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); }
  function ratio(a, b) { var l1 = lum(a), l2 = lum(b); if (l1 < l2) { var t = l1; l1 = l2; l2 = t; } return (l1 + 0.05) / (l2 + 0.05); }
  var fails = [], checked = 0, seen = new Set();
  var walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  while (walker.nextNode()) {
    var n = walker.currentNode;
    if (!n.nodeValue.trim()) continue;
    var el = n.parentElement;
    if (!el || seen.has(el)) continue;
    seen.add(el);
    var cs = getComputedStyle(el);
    if (cs.visibility === 'hidden' || cs.display === 'none' || el.closest('[hidden]') || el.closest('script,style,noscript')) continue;
    var rect = el.getBoundingClientRect();
    if (!rect.width || !rect.height) continue;
    if (el.closest('.hero,.cta,.site-footer')) continue;
    var fg = parse(cs.color), bg = bgOf(el);
    if (!bg || !fg) continue;
    var eff = fg.a < 1 ? over(fg, bg) : fg;
    var r = ratio(eff, bg), size = parseFloat(cs.fontSize), bold = parseInt(cs.fontWeight, 10) >= 700;
    var need = (size >= 24 || (size >= 18.66 && bold)) ? 3 : 4.5;
    checked++;
    if (r < need) fails.push({ t: n.nodeValue.trim().slice(0, 40), r: Math.round(r * 100) / 100, need: need, cls: el.className && el.className.toString().slice(0, 40) });
  }
  return { checked: checked, failCount: fails.length, fails: fails.slice(0, 25) };
};
