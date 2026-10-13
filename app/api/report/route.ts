import { NextResponse } from 'next/server'
import { scanUrl } from '@/lib/xlogs/engine.mjs'
import { normalizeAndValidate } from '@/lib/xlogs/ssrf.mjs'

export const runtime = 'nodejs'

function escapeHtml(value: unknown) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char] ?? char))
}

function reportHtml(result: any) {
  const rows = (result.findings ?? []).map((finding: any) => `<article><h2>${escapeHtml(finding.title)}</h2><p><strong>${escapeHtml(finding.severity)} · ${escapeHtml(finding.confidence)}</strong></p><p>${escapeHtml(finding.plain)}</p><p><b>Affected resource:</b> ${escapeHtml(finding.location || 'Not supplied')}</p><p><b>Evidence:</b> ${escapeHtml(finding.observed || 'Not supplied')}</p><p><b>Remediation:</b> ${escapeHtml((finding.fixSteps ?? []).join(' ') || 'Inspect the repository before editing.')}</p></article>`).join('')
  return `<!doctype html><html><head><meta charset="utf-8"><title>SYKER AI report · ${escapeHtml(result.url)}</title><style>body{font:15px/1.6 Arial;color:#211b17;max-width:900px;margin:48px auto;padding:0 24px}header{border-bottom:4px solid #d8662c;padding-bottom:18px}h1{font-size:32px}h2{font-size:20px;color:#9a431d}article{border:1px solid #ddd3ca;border-radius:10px;padding:18px;margin:18px 0}small{color:#6e655d}</style></head><body><header><h1>SYKER AI</h1><p>Evidence-first website security report</p><p><b>Target:</b> ${escapeHtml(result.url)}<br><b>Generated:</b> ${escapeHtml(new Date().toISOString())}<br><b>Status:</b> ${escapeHtml(result.verdict?.headline || 'Completed scan')}</p></header><h2>Executive summary</h2><p>${escapeHtml(result.verdict?.summary || `${result.findings?.length ?? 0} findings returned by the read-only scanner.`)}</p><h2>Findings</h2>${rows || '<p>No findings were returned.</p>'}<p><small>This report reflects an external observation and is not a security guarantee. Scan only systems you own or are authorized to test.</small></p></body></html>`
}

function pdfText(result: any) {
  const lines = ['SYKER AI — Website Security Report', `Target: ${result.url}`, `Generated: ${new Date().toISOString()}`, '', result.verdict?.headline || 'Completed scan', result.verdict?.summary || '', '']
  for (const finding of result.findings ?? []) lines.push(`[${String(finding.severity || 'info').toUpperCase()}] ${finding.title}`, `Resource: ${finding.location || 'Not supplied'}`, `Evidence: ${finding.observed || 'Not supplied'}`, `Remediation: ${(finding.fixSteps || []).join(' ')}`, '')
  const esc = (text: string) => text.replace(/\\/g, '\\\\').replace(/[()]/g, (c) => `\\${c}`).replace(/[^\x20-\x7E]/g, '?')
  const stream = `BT /F1 10 Tf 48 760 Td ${lines.map((line) => `(${esc(line.slice(0, 110))}) Tj 0 -14 Td`).join(' ')} ET`
  const objects = [`1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj`, `2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj`, `3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1 4 0 R>>>>/Contents 5 0 R>>endobj`, `4 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj`, `5 0 obj<</Length ${stream.length}>>stream\n${stream}\nendstream endobj`]
  let pdf = '%PDF-1.4\n'; const offsets = [0]
  for (const object of objects) { offsets.push(pdf.length); pdf += object + '\n' }
  const xref = pdf.length; pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n${offsets.slice(1).map((offset) => `${String(offset).padStart(10, '0')} 00000 n `).join('\n')}\ntrailer<</Size ${objects.length + 1}/Root 1 0 R>>\nstartxref\n${xref}\n%%EOF`
  return pdf
}

export async function GET(request: Request) {
  try {
    const params = await (async () => new URL(request.url).searchParams)()
    const validated = normalizeAndValidate(params.get('url') || '')
    if (!validated.ok) return new NextResponse(validated.reason, { status: 400 })
    const result = await scanUrl(validated.url)
    const format = params.get('format') === 'pdf' ? 'pdf' : 'html'
    if (format === 'pdf') return new NextResponse(pdfText(result), { headers: { 'Content-Type': 'application/pdf', 'Content-Disposition': 'attachment; filename="syker-ai-report.pdf"' } })
    return new NextResponse(reportHtml(result), { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Content-Disposition': 'attachment; filename="syker-ai-report.html"' } })
  } catch (error) { return new NextResponse(error instanceof Error ? error.message : 'Report generation failed.', { status: 500 }) }
}
