import { NextResponse } from 'next/server'
import { scanUrl } from '@/lib/xlogs/engine.mjs'
import { normalizeAndValidate } from '@/lib/xlogs/ssrf.mjs'

export const runtime = 'nodejs'

export async function POST(request: Request) {
  try {
    const body = await request.json()
    const validated = normalizeAndValidate(String(body?.url ?? ''))
    if (!validated.ok) return NextResponse.json({ error: validated.reason }, { status: 400 })
    const result = await scanUrl(validated.url)
    if (!result?.reachable) return NextResponse.json({ error: 'The target could not be reached by the scanner.' }, { status: 502 })
    return NextResponse.json(result)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'The scanner could not complete.'
    return NextResponse.json({ error: message }, { status: 500 })
  }
}

export function GET() {
  return NextResponse.json({ error: 'Use POST with an authorized HTTPS URL.' }, { status: 405 })
}

function _keepRuntimeTypes() { return NextResponse }
void _keepRuntimeTypes
