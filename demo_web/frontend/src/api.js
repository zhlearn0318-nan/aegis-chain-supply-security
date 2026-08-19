const envBase = typeof import.meta.env !== 'undefined'
  ? import.meta.env.VITE_API_BASE
  : ''

export const API_V1_PREFIX = '/api/v1'

export class GatewayApiError extends Error {
  constructor({ status = 0, code = 'HTTP_ERROR', message = '请求失败', details = null, cause } = {}) {
    super(message, cause ? { cause } : undefined)
    this.name = 'GatewayApiError'
    this.status = status
    this.code = code
    this.details = details
  }
}

function cleanBaseUrl(baseUrl) {
  return String(baseUrl || '').replace(/\/+$/, '')
}

async function readJson(response) {
  const contentType = response.headers.get('content-type') || ''
  if (!contentType.toLowerCase().includes('json')) return null
  try {
    return await response.json()
  } catch {
    return null
  }
}

function apiUrl(baseUrl, path) {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`
  return `${cleanBaseUrl(baseUrl)}${API_V1_PREFIX}${normalizedPath}`
}

export function normalizeApiError(error) {
  if (error instanceof GatewayApiError) return error
  return new GatewayApiError({
    code: 'CLIENT_ERROR',
    message: error instanceof Error ? error.message : String(error || '未知客户端错误'),
    cause: error instanceof Error ? error : undefined,
  })
}

export function createGatewayClient({
  baseUrl = envBase || '',
  fetchImpl = globalThis.fetch,
} = {}) {
  if (typeof fetchImpl !== 'function') {
    throw new TypeError('createGatewayClient requires a fetch implementation')
  }

  async function request(path, options) {
    let response
    try {
      response = await fetchImpl(apiUrl(baseUrl, path), options)
    } catch (cause) {
      throw new GatewayApiError({
        code: 'NETWORK_ERROR',
        message: '无法连接供应链安全网关，请确认后端服务已启动。',
        cause,
      })
    }

    const payload = await readJson(response)
    if (!response.ok) {
      const problem = payload?.api_version === 'v1' ? payload.error : null
      throw new GatewayApiError({
        status: response.status,
        code: problem?.code || 'HTTP_ERROR',
        message: problem?.message || payload?.detail || `请求失败 (${response.status})`,
        details: problem?.details ?? null,
      })
    }

    if (payload?.api_version !== 'v1' || !Object.hasOwn(payload, 'data')) {
      throw new GatewayApiError({
        status: response.status,
        code: 'INVALID_API_ENVELOPE',
        message: '网关返回了无法识别的 v1 响应，已停止解析。',
        details: { expected: '{ api_version: "v1", data: ... }' },
      })
    }
    return payload.data
  }

  function upload(path, fields) {
    const form = new FormData()
    Object.entries(fields).forEach(([name, value]) => {
      if (value) form.append(name, value)
    })
    return request(path, { method: 'POST', body: form })
  }

  function adminRequest(path, adminToken, options = {}) {
    const headers = new Headers(options.headers || {})
    headers.set('X-Aegis-Admin-Token', String(adminToken || ''))
    return request(path, { ...options, headers })
  }

  return Object.freeze({
    health: () => request('/health'),
    presets: () => request('/presets'),
    listScans: (limit = 12) => request(`/scans?limit=${encodeURIComponent(limit)}`),
    getScan: (jobId) => request(`/scans/${encodeURIComponent(jobId)}`),
    runPreset: (presetId) => request(`/scans/preset/${encodeURIComponent(presetId)}`, { method: 'POST' }),
    uploadSkill: (file) => upload('/scans/skill', { file }),
    uploadMcp: (mcpJson, requirements) => upload('/scans/mcp', { mcp_json: mcpJson, requirements }),
    uploadDependency: (requirements) => upload('/scans/dependency', { requirements }),
    exportUrl: (jobId, format) => `${apiUrl(baseUrl, `/scans/${encodeURIComponent(jobId)}/export`)}?format=${encodeURIComponent(format)}`,
    startDynamicAudit: (adminToken) => adminRequest('/admin/dynamic-audits', adminToken, { method: 'POST' }),
    listDynamicAudits: (adminToken, limit = 12) => adminRequest(`/admin/dynamic-audits?limit=${encodeURIComponent(limit)}`, adminToken),
    getDynamicAudit: (adminToken, jobId) => adminRequest(`/admin/dynamic-audits/${encodeURIComponent(jobId)}`, adminToken),
  })
}

export const gatewayApi = createGatewayClient()
