// -------------------------
// WebCheck Pro Backend
// -------------------------
const express = require('express')
const rateLimit = require('express-rate-limit')
const helmet = require('helmet')
const cors = require('cors')
const PQueue = require('p-queue').default
const { LRUCache } = require('lru-cache')
const puppeteer = require('puppeteer')
let lighthouse = require('lighthouse')
if (lighthouse.default) lighthouse = lighthouse.default
const chromeLauncher = require('chrome-launcher')
const axeSource = require('axe-core').source
const fetch = require('node-fetch')

// App setup
const app = express()
app.use(express.json())
app.use(cors())
app.use(helmet())

// Rate limiting
app.use('/audit', rateLimit({ windowMs: 60 * 1000, max: 6 }))
app.use('/report', rateLimit({ windowMs: 60 * 1000, max: 6 }))

// Cache + queue
const cache = new LRUCache({ max: 200, ttl: 1000 * 60 * 15 })
const queue = new PQueue({ concurrency: 1 })

// Normalize URL
function normalize(u) {
  try {
    if (!/^https?:\/\//i.test(u)) u = 'https://' + u
    return new URL(u).toString()
  } catch {
    return null
  }
}

// Smart Scoring Algorithm
function computeSmartScore({ performance, seo, security, accessibility, headerChecks, axe }) {
  const baseScore =
    0.35 * (performance || 0) +
    0.25 * (seo || 0) +
    0.25 * (security || 0) +
    0.15 * (accessibility || 0)

  let penalties = 0
  let suggestions = []

  if (headerChecks.length > 0) {
    penalties += 5
    suggestions.push("Add missing security headers (CSP, HSTS, X-Frame-Options).")
  }

  if (axe && axe.violations && axe.violations.length > 0) {
    penalties += Math.min(axe.violations.length * 2, 15)
    suggestions.push("Fix accessibility issues (missing alt tags, ARIA roles, contrast, etc).")
  }

  if (performance < 50) suggestions.push("Optimize images, enable caching, and minify scripts.")
  if (seo < 70) suggestions.push("Add meta tags, improve titles, and fix broken links.")
  if (accessibility < 70) suggestions.push("Improve keyboard navigation and ARIA attributes.")
  if (security < 70) suggestions.push("Implement HTTPS, strong headers, and input sanitization.")

  const finalScore = Math.max(0, Math.min(100, Math.round(baseScore - penalties)))
  let grade = "C"
  let label = "Needs Improvement"
  if (finalScore >= 90) { grade = "A+"; label = "Excellent" }
  else if (finalScore >= 80) { grade = "A"; label = "Great" }
  else if (finalScore >= 70) { grade = "B"; label = "Good" }
  else if (finalScore >= 60) { grade = "C"; label = "Fair" }
  else { grade = "D"; label = "Poor" }

  return { finalScore, grade, label, penalties, suggestions }
}

// Run Lighthouse
async function runLighthouseAudit(target) {
  const chrome = await chromeLauncher.launch({ chromeFlags: ['--headless', '--no-sandbox'] })
  const opts = { port: chrome.port, output: 'json', logLevel: 'error' }
  const runnerResult = await lighthouse(target, opts)
  await chrome.kill()
  return runnerResult.lhr
}

// Run Axe Accessibility Scan
async function runAxeOnPage(target) {
  const browser = await puppeteer.launch({ args: ['--no-sandbox'] })
  const page = await browser.newPage()
  await page.goto(target, { waitUntil: 'networkidle2', timeout: 30000 })
  await page.evaluate(axeSource)
  const results = await page.evaluate(async () => await axe.run())
  await browser.close()
  return results
}

// Analyze headers
function analyzeHeaders(headers) {
  const checks = []
  const has = (h) => !!headers[h]
  if (!has('content-security-policy')) checks.push('Missing CSP')
  if (!has('strict-transport-security')) checks.push('Missing HSTS')
  if (!has('x-frame-options')) checks.push('Missing X-Frame-Options')
  if (!has('x-content-type-options')) checks.push('Missing X-Content-Type-Options')
  return checks
}

// Health check
app.get('/health', (req, res) => {
  res.json({ ok: true, message: 'WebCheck Pro backend healthy' })
})

// Audit endpoint
app.get('/audit', async (req, res) => {
  const target = normalize(req.query.url)
  if (!target) return res.status(400).json({ error: 'Invalid url' })

  const cached = cache.get(target)
  if (cached && cached.data) {
    return res.json({ ...cached.data, cached: true })
  }

  try {
    const result = await queue.add(async () => {
      console.log(`🔍 Starting audit for ${target}`)
      const lhr = await runLighthouseAudit(target)
      const axe = await runAxeOnPage(target)

      // Headers
      let headerChecks = []
      try {
        const fetchResp = await fetch(target, { redirect: "follow" })
        headerChecks = analyzeHeaders(Object.fromEntries(fetchResp.headers.entries()))
      } catch (err) {
        console.warn("⚠️ Header fetch failed:", err.message)
      }

      // Extract scores
      const perfScore = lhr.categories?.performance?.score ? Math.round(lhr.categories.performance.score * 100) : 0
      const accScore = lhr.categories?.accessibility?.score ? Math.round(lhr.categories.accessibility.score * 100) : 0
      const seoScore = lhr.categories?.seo?.score ? Math.round(lhr.categories.seo.score * 100) : 0
      const secGuess = 80 + (headerChecks.length ? -10 : 0)

      // Compute smart score
      const { finalScore, grade, label, penalties, suggestions } =
        computeSmartScore({ performance: perfScore, seo: seoScore, security: secGuess, accessibility: accScore, headerChecks, axe })

      const data = {
        url: target,
        timestamp: new Date().toISOString(),
        performance: perfScore,
        accessibility: accScore,
        seo: seoScore,
        security: secGuess,
        headerChecks,
        axeSummary: axe?.violations ? `${axe.violations.length} issues` : 'N/A',
        axeDetails: axe?.violations || [],
        smartScore: finalScore,
        smartGrade: grade,
        smartLabel: label,
        penalties,
        suggestions,
        radar: { performance: perfScore, seo: seoScore, security: secGuess, accessibility: accScore }
      }

      cache.set(target, { data })
      return data
    })
    return res.json(result)
  } catch (err) {
    console.error('❌ Audit error', err)
    return res.status(500).json({ error: 'Audit failed', message: err.message })
  }
})

// PDF Report
app.get('/report', async (req, res) => {
  const target = normalize(req.query.url)
  if (!target) return res.status(400).json({ error: 'Invalid url' })

  const cached = cache.get(target)
  const data = cached?.data || {}

  const html = `
    <!doctype html>
    <html>
    <head><meta charset="utf-8"><title>Report</title></head>
    <body>
      <h1>WebCheck Pro Report for ${target}</h1>
      <pre>${JSON.stringify(data, null, 2)}</pre>
    </body>
    </html>
  `
  const browser = await puppeteer.launch({ args: ['--no-sandbox'] })
  const page = await browser.newPage()
  await page.setContent(html, { waitUntil: 'networkidle0' })
  const pdf = await page.pdf({ format: 'A4' })
  await browser.close()

  res.set({ 'Content-Type': 'application/pdf', 'Content-Length': pdf.length })
  res.send(pdf)
})

// Start server
const port = process.env.PORT || 4000
app.listen(port, () => console.log(`✅ Backend running on http://localhost:${port}`))
