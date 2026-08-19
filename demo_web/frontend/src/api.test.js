import assert from 'node:assert/strict'
import test from 'node:test'

import { GatewayApiError, createGatewayClient, normalizeApiError } from './api.js'

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  })
}

test('unwraps a valid v1 success envelope', async () => {
  const calls = []
  const client = createGatewayClient({
    baseUrl: 'http://test.local/',
    fetchImpl: async (url, options) => {
      calls.push({ url, options })
      return jsonResponse({ api_version: 'v1', data: { status: 'ready' } })
    },
  })

  assert.deepEqual(await client.health(), { status: 'ready' })
  assert.equal(calls[0].url, 'http://test.local/api/v1/health')
})

test('treats HTTP 202 scan creation as accepted success', async () => {
  const client = createGatewayClient({
    fetchImpl: async () => jsonResponse({
      api_version: 'v1',
      data: { id: 'job-1', status: 'queued', decision: 'UNKNOWN' },
    }, 202),
  })

  const job = await client.runPreset('risk sample')
  assert.equal(job.status, 'queued')
  assert.equal(job.id, 'job-1')
})

test('retains v1 error status, code, message and details', async () => {
  const client = createGatewayClient({
    fetchImpl: async () => jsonResponse({
      api_version: 'v1',
      error: {
        code: 'SCAN_NOT_FOUND',
        message: '扫描任务不存在',
        details: { job_id: 'missing' },
      },
    }, 404),
  })

  await assert.rejects(
    client.getScan('missing'),
    (error) => {
      assert.ok(error instanceof GatewayApiError)
      assert.equal(error.status, 404)
      assert.equal(error.code, 'SCAN_NOT_FOUND')
      assert.equal(error.message, '扫描任务不存在')
      assert.deepEqual(error.details, { job_id: 'missing' })
      return true
    },
  )
})

test('fails closed when a successful response lacks the v1 envelope', async () => {
  const client = createGatewayClient({
    fetchImpl: async () => jsonResponse({ status: 'ready' }),
  })

  await assert.rejects(
    client.health(),
    (error) => error.code === 'INVALID_API_ENVELOPE' && error.status === 200,
  )
})

test('reports non-JSON and network failures with client-side codes', async () => {
  const httpClient = createGatewayClient({
    fetchImpl: async () => new Response('bad gateway', { status: 502 }),
  })
  await assert.rejects(httpClient.health(), (error) => error.code === 'HTTP_ERROR' && error.status === 502)

  const networkClient = createGatewayClient({
    fetchImpl: async () => { throw new Error('connection refused') },
  })
  await assert.rejects(networkClient.health(), (error) => error.code === 'NETWORK_ERROR' && error.status === 0)
})

test('builds encoded v1 export URLs', () => {
  const client = createGatewayClient({ baseUrl: 'http://test.local/', fetchImpl: async () => null })
  assert.equal(
    client.exportUrl('job / 1', 'md'),
    'http://test.local/api/v1/scans/job%20%2F%201/export?format=md',
  )
})

test('normalizes local validation messages without discarding them', () => {
  const error = normalizeApiError(new Error('请选择文件。'))
  assert.equal(error.code, 'CLIENT_ERROR')
  assert.equal(error.message, '请选择文件。')
})

test('sends the administrator token only in the dedicated header', async () => {
  const calls = []
  const token = 'admin-secret-memory-only'
  const client = createGatewayClient({
    baseUrl: 'http://test.local',
    fetchImpl: async (url, options) => {
      calls.push({ url, options })
      return jsonResponse({
        api_version: 'v1',
        data: { id: 'dynamic-1', status: 'queued' },
      }, 202)
    },
  })

  await client.startDynamicAudit(token)
  const call = calls[0]
  assert.equal(call.url, 'http://test.local/api/v1/admin/dynamic-audits')
  assert.equal(call.options.method, 'POST')
  assert.equal(call.options.body, undefined)
  assert.equal(call.options.headers.get('X-Aegis-Admin-Token'), token)
  assert.ok(!call.url.includes(token))
})

test('uses the administrator header for dynamic history and detail requests', async () => {
  const calls = []
  const client = createGatewayClient({
    fetchImpl: async (url, options) => {
      calls.push({ url, options })
      return jsonResponse({ api_version: 'v1', data: [] })
    },
  })

  await client.listDynamicAudits('memory-token', 7)
  await client.getDynamicAudit('memory-token', 'job / 1')
  assert.equal(calls[0].url, '/api/v1/admin/dynamic-audits?limit=7')
  assert.equal(calls[1].url, '/api/v1/admin/dynamic-audits/job%20%2F%201')
  for (const call of calls) {
    assert.equal(call.options.headers.get('X-Aegis-Admin-Token'), 'memory-token')
  }
})
