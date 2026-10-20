#!/usr/bin/env node
// Renders the raster brand files in frontend/public/ from the vector ones:
//   apple-touch-icon.png (180), icon-192.png, icon-512.png, icon-maskable-512.png (safe padding),
//   favicon.ico (16/32/48, PNG-in-ICO).
//
//   NODE_PATH=<dir with node_modules/puppeteer-core> \
//   BROWSER="/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge" \
//   node tools/brand_rasters.mjs
//
// Rasteriser: a headless Chromium-based browser (Edge or Chrome) driven by puppeteer-core -- the
// repo needs no image library for this and the browser is what draws the SVGs for users. A tools-only
// dependency; the app and its tests never run this. Output is committed; rerun only if the mark changes.

import { createRequire } from 'node:module'
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
const puppeteer = require('puppeteer-core')
const PUBLIC = join(dirname(fileURLToPath(import.meta.url)), '..', 'frontend', 'public')
const BROWSER = process.env.BROWSER || '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge'

const BG = '#1E293B'
// The app-icon look: dark tile, light shield, amber tick (the dark-mode colours of mark.svg).
const mark = readFileSync(join(PUBLIC, 'mark.svg'), 'utf8')
const favicon = readFileSync(join(PUBLIC, 'favicon.svg'), 'utf8')

const html = (svg, size, inner, bg, radius = 0) =>
  `<html><body style="margin:0;background:transparent"><div style="width:${size}px;height:${size}px;background:${bg};border-radius:${radius}px;display:flex;align-items:center;justify-content:center">` +
  `<div style="width:${inner}px;height:${inner}px">${svg}</div></div></body></html>`

async function png(page, size, doc, transparent = false) {
  await page.setViewport({ width: size, height: size, deviceScaleFactor: 1 })
  await page.setContent(doc)
  return page.screenshot({ type: 'png', omitBackground: transparent, clip: { x: 0, y: 0, width: size, height: size } })
}

const browser = await puppeteer.launch({ executablePath: BROWSER, headless: true, args: ['--force-dark-mode', '--no-first-run'] })
try {
  const page = await browser.newPage()
  await page.emulateMediaFeatures([{ name: 'prefers-color-scheme', value: 'dark' }])
  const fit = (s) => s.replace('<svg ', '<svg width="100%" height="100%" ')
  const files = {
    'apple-touch-icon.png': await png(page, 180, html(fit(mark), 180, 126, BG)),
    'icon-192.png': await png(page, 192, html(fit(mark), 192, 134, BG)),
    'icon-512.png': await png(page, 512, html(fit(mark), 512, 358, BG)),
    // Maskable: the artwork stays inside the central 80% circle (~58% of the side), the rest is plain background.
    'icon-maskable-512.png': await png(page, 512, html(fit(mark), 512, 290, BG)),
  }
  for (const [name, data] of Object.entries(files)) writeFileSync(join(PUBLIC, name), data)

  // favicon.ico: dark rounded tile + the 16 px simplified shield, at 16/32/48.
  const sizes = [16, 32, 48]
  const entries = []
  for (const s of sizes) {
    const dark = favicon.replace('<style>', '<style>.f{fill:#E2E8F0}.t{stroke:#F59E0B}').replace(/@media[^}]*\{[^}]*\}[^}]*\}/, '')
    entries.push({ size: s, data: await png(page, s, html(fit(dark), s, Math.round(s * 0.78), BG, Math.round(s * 0.22)), true) })
  }
  const header = Buffer.alloc(6)
  header.writeUInt16LE(0, 0); header.writeUInt16LE(1, 2); header.writeUInt16LE(entries.length, 4)
  let offset = 6 + 16 * entries.length
  const dir = entries.map((e) => {
    const d = Buffer.alloc(16)
    d.writeUInt8(e.size, 0); d.writeUInt8(e.size, 1); d.writeUInt16LE(1, 4); d.writeUInt16LE(32, 6)
    d.writeUInt32LE(e.data.length, 8); d.writeUInt32LE(offset, 12)
    offset += e.data.length
    return d
  })
  writeFileSync(join(PUBLIC, 'favicon.ico'), Buffer.concat([header, ...dir, ...entries.map((e) => e.data)]))
  console.log('wrote', Object.keys(files).join(', '), 'and favicon.ico', sizes.join('/'))
} finally {
  await browser.close()
}
