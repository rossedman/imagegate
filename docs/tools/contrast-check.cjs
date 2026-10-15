// Contrast check for the docs site: loads every page in the sitemap in both
// colour schemes at phone width and fails if any visible text is below WCAG
// AA (4.5:1, or 3:1 for large text) against its actual background.
//
//   make docs-contrast      (builds the site, serves it, runs this)
//   node docs/tools/contrast-check.cjs http://127.0.0.1:8000/
//
// Needs Node and Playwright (npm i -g playwright && npx playwright install chromium).
const { chromium } = require('playwright');
(async () => {
  const base = (process.argv[2] || 'http://127.0.0.1:8000/').replace(/\/?$/, '/');
  const b = await chromium.launch(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
  const sm = await (await b.newPage()).request.get(base + 'sitemap.xml');
  const pages = [...(await sm.text()).matchAll(/<loc>([^<]+)<\/loc>/g)].map(m => new URL(m[1]).pathname.replace(/^\/[^/]+\//, ''));
  let total = 0;
  for (const scheme of ['dark', 'light']) {
    const p = await b.newPage({ viewport: { width: 390, height: 844 }, colorScheme: scheme });
    for (const path of pages) {
      await p.goto(base + path, { waitUntil: 'networkidle' });
      await p.waitForTimeout(800);
      const bad = await p.evaluate(() => {
        const parse = c => { const m = c.match(/rgba?\(([^)]+)\)/); if (!m) return null; const v = m[1].split(/[ ,/]+/).filter(Boolean).map(Number); return { r: v[0], g: v[1], b: v[2], a: v.length > 3 ? v[3] : 1 }; };
        const lum = c => { const f = x => { x /= 255; return x <= 0.03928 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
        const blend = (fg, bg) => ({ r: fg.r * fg.a + bg.r * (1 - fg.a), g: fg.g * fg.a + bg.g * (1 - fg.a), b: fg.b * fg.a + bg.b * (1 - fg.a), a: 1 });
        const bgOf = el => { let layers = []; for (let e = el; e; e = e.parentElement) { const c = parse(getComputedStyle(e).backgroundColor); if (c && c.a > 0) { layers.push(c); if (c.a >= 1) break; } } let bg = { r: 255, g: 255, b: 255, a: 1 }; for (const l of layers.reverse()) bg = blend(l, bg); return bg; };
        const out = [];
        const walker = document.createTreeWalker(document.querySelector('.md-container') || document.body, NodeFilter.SHOW_TEXT);
        const seen = new Set();
        while (walker.nextNode()) {
          const t = walker.currentNode; const el = t.parentElement;
          if (!t.textContent.trim() || seen.has(el)) continue; seen.add(el);
          const cs = getComputedStyle(el); const r = el.getBoundingClientRect();
          if (r.width === 0 || r.height === 0 || cs.visibility === 'hidden' || cs.display === 'none') continue;
          if (el.closest('svg') && !el.closest('.mermaid')) continue;
          let opacity = 1; for (let e = el; e; e = e.parentElement) opacity *= parseFloat(getComputedStyle(e).opacity);
          if (opacity < 0.05) continue;
          const isSvg = el instanceof SVGElement;
          let fg = parse(isSvg ? (cs.fill && cs.fill !== 'none' ? cs.fill : cs.color) : cs.color); if (!fg) continue;
          fg.a *= opacity;
          const bg = bgOf(el); const f = blend(fg, bg);
          const L1 = lum(f), L2 = lum(bg); const ratio = (Math.max(L1, L2) + 0.05) / (Math.min(L1, L2) + 0.05);
          const size = parseFloat(cs.fontSize), bold = parseInt(cs.fontWeight) >= 700;
          const need = (size >= 24 || (size >= 18.66 && bold)) ? 3 : 4.5;
          if (ratio < need) out.push(`${ratio.toFixed(2)} <${el.tagName.toLowerCase()}.${(el.className && el.className.baseVal !== undefined ? el.className.baseVal : el.className) || ''}> ${cs.color} on rgb(${bg.r|0},${bg.g|0},${bg.b|0}) "${t.textContent.trim().slice(0, 40)}"`);
        }
        return out;
      });
      if (bad.length) { console.log(`--- ${scheme} /${path} (${bad.length})`); for (const l of [...new Set(bad)].slice(0, 12)) console.log('  ' + l); }
      total += bad.length;
    }
  }
  console.log(`checked ${pages.length} pages x 2 schemes: ${total} low-contrast elements`);
  await b.close();
  process.exit(total ? 1 : 0);
})();
