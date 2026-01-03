import React, { useEffect, useMemo, useRef, useState } from 'react'
import {
  Header, HeaderName, HeaderGlobalBar, HeaderGlobalAction,
  Content, Theme,
  Button, TextArea, Dropdown, ComboBox, Modal, Tabs, Tab, Tile, Tag, Stack,
  DataTable, TableContainer, Table, TableHead, TableRow, TableHeader, TableBody, TableCell,
  InlineNotification, TextInput, Toggle, CodeSnippet,
  SideNav, SideNavItems, SideNavLink
} from '@carbon/react'
import { Chat, Settings, Menu, Information, Logout } from '@carbon/icons-react'
import { BrowserRouter, Routes, Route, Navigate, useLocation, useNavigate } from 'react-router-dom'
import './overrides.css'

// Optional (client-side) Excel export
import * as XLSX from 'xlsx'

const SETTINGS_KEY = 'mx_settings_v5'
const CHAT_STORAGE_KEY = 'mx_chat_v1'
const DEFAULT_SETTINGS = {
  mode: 'maximo',
  maximo: { baseUrl:'', apiKey:'', defaultSite:'', defaultTenant:'default' },
  ai: { provider:'openai', model:'gpt-4o-mini', system:'', temperature:0.7 },
  mcp: { enableTools:false, url:'' },
  results: {
    showReport: true,
    enableExcelDownload: true,
    enableOpenInMaximo: true,
  },
  maximoUi: {
    // Per-OS overrides. Template supports: {baseUrl} {os} {id} {field}
    // Example: "{baseUrl}/maximo/ui/?event=loadapp&value={id}&app=wotrack"
    recordLinkTemplates: {},
  },
  avatars: { default:'', user:'', openai:'', anthropic:'', gemini:'', watsonx:'', mistral:'', deepseek:'' }
}

const NAV_EXPANDED_W = 256
const NAV_COLLAPSED_W = 56

const PROMPTS = [
  { id:'locations', label:'Locations', prompt:'Show me all locations' },
  { id:'assets', label:'Assets', prompt:'Show me all assets' },
  { id:'open_wos', label:'Open WOs', prompt:'Show me all open work orders' },
  { id:'cm_wos', label:'Corrective WOs', prompt:'Show me all corrective work orders' },
  { id:'srs', label:'Service Requests', prompt:'Show me all service requests' },
  { id:'pms', label:'Preventive Maintenance', prompt:'show me all preventive maintenance (PM) records' },
  { id:'jp', label:'Job Plans', prompt:'show me all job plans (JP)' },
  { id:'create_wo', label:'Create WO', action:'create_wo', kind:'danger' },
  { id:'create_sr', label:'Create SR', action:'create_sr', kind:'danger' },
  { id:'analyze_last', label:'Analyze / Summarize last response', action:'analyze_last', kind:'danger' },
]

function isLikelyImageUrl(u) {
  const s = String(u || '').trim().toLowerCase()
  if (!s) return false
  if (s.startsWith('data:image/')) return true
  if (s.startsWith('blob:')) return true
  // Common image extensions (keep this simple)
  return /\.(png|jpe?g|gif|webp|svg)(\?.*)?$/.test(s)
}

// If the user pastes a normal website URL, show a best-effort site icon (favicon).
function resolveAvatarSrc(input) {
  const v = String(input || '').trim()
  if (!v) return ''
  if (v.startsWith('data:') || v.startsWith('blob:')) return v
  if (isLikelyImageUrl(v)) return v
  try {
    const u = new URL(v)
    const origin = u.origin
    // Google favicon service (simple + reliable; requires CSP img-src to allow https)
    return `https://www.google.com/s2/favicons?domain_url=${encodeURIComponent(origin)}&sz=128`
  } catch {
    return v
  }
}

// Small helper used across the UI when endpoints return JSON as a string.
// (e.g., some MCP responses wrap tool output in content[0].text)
function safeJsonParse(text) {
  if (text == null) return null
  const s0 = String(text).trim()
  if (!s0) return null
  // 1) plain JSON
  try { return JSON.parse(s0) } catch {}

  // 2) JSON wrapped in markdown code fences
  const unfenced = s0.replace(/^```[a-zA-Z0-9_-]*\s*/,'').replace(/\s*```$/,'').trim()
  if (unfenced && unfenced !== s0) {
    try { return JSON.parse(unfenced) } catch {}
  }

  // 3) best-effort extraction of first JSON object/array substring
  const firstObj = s0.indexOf('{')
  const lastObj = s0.lastIndexOf('}')
  if (firstObj >= 0 && lastObj > firstObj) {
    const sub = s0.slice(firstObj, lastObj + 1)
    try { return JSON.parse(sub) } catch {}
  }
  const firstArr = s0.indexOf('[')
  const lastArr = s0.lastIndexOf(']')
  if (firstArr >= 0 && lastArr > firstArr) {
    const sub = s0.slice(firstArr, lastArr + 1)
    try { return JSON.parse(sub) } catch {}
  }
  return null
}

const PROVIDERS = [
  { id:'openai', label:'OpenAI' },
  { id:'anthropic', label:'Anthropic' },
  { id:'gemini', label:'Gemini' },
  { id:'watsonx', label:'IBM watsonx' },
  { id:'mistral', label:'Mistral' },
  { id:'deepseek', label:'DeepSeek' },
]

function loadSettings() {
  try {
    const raw = localStorage.getItem(SETTINGS_KEY)
    if (!raw) return null
    const s = JSON.parse(raw) || {}
    return {
      ...DEFAULT_SETTINGS,
      ...s,
      maximo: { ...DEFAULT_SETTINGS.maximo, ...(s.maximo || {}) },
      ai: { ...DEFAULT_SETTINGS.ai, ...(s.ai || {}) },
      mcp: { ...DEFAULT_SETTINGS.mcp, ...(s.mcp || {}) },
      results: { ...DEFAULT_SETTINGS.results, ...(s.results || {}) },
      maximoUi: { ...DEFAULT_SETTINGS.maximoUi, ...(s.maximoUi || {}) },
      avatars: { ...DEFAULT_SETTINGS.avatars, ...(s.avatars || {}) },
    }
  } catch { return null }
}
function persistSettings(v) { localStorage.setItem(SETTINGS_KEY, JSON.stringify(v)) }

async function apiAgentChat(payload) {
  const r = await fetch('/api/agent/chat', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(payload) })
  const raw = await r.text()
  let j=null; try{ j=JSON.parse(raw) }catch{}
  if(!r.ok) throw new Error((j && (j.detail||j.error)) ? (j.detail||j.error) : (raw||`HTTP ${r.status}`))
  if(!j) throw new Error(`Unexpected response (not JSON): ${raw.slice(0,200)}`)
  return j
}

async function apiAnalyzeLast(payload) {
  const r = await fetch('/api/agent/analyze-last', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(payload) })
  const raw = await r.text()
  let j=null; try{ j=JSON.parse(raw) }catch{}
  if(!r.ok) throw new Error((j && (j.detail||j.error)) ? (j.detail||j.error) : (raw||`HTTP ${r.status}`))
  if(!j) throw new Error(`Unexpected response (not JSON): ${raw.slice(0,200)}`)
  return j
}

async function apiValueListTenants(payload) {
  const r = await fetch('/api/agent/value-list/tenants', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(payload) })
  const raw = await r.text()
  let j=null; try{ j=JSON.parse(raw) }catch{}
  if(!r.ok) throw new Error((j && (j.detail||j.error)) ? (j.detail||j.error) : (raw||`HTTP ${r.status}`))
  if(!j) throw new Error(`Unexpected response (not JSON): ${raw.slice(0,200)}`)
  return j
}

async function apiValueListAssets(payload) {
  const r = await fetch('/api/agent/value-list/assets', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(payload) })
  const raw = await r.text()
  let j=null; try{ j=JSON.parse(raw) }catch{}
  if(!r.ok) throw new Error((j && (j.detail||j.error)) ? (j.detail||j.error) : (raw||`HTTP ${r.status}`))
  if(!j) throw new Error(`Unexpected response (not JSON): ${raw.slice(0,200)}`)
  return j
}

async function apiCreateRecord(payload) {
  const r = await fetch('/api/agent/create-record', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(payload) })
  const raw = await r.text()
  let j=null; try{ j=JSON.parse(raw) }catch{}
  if(!r.ok) throw new Error((j && (j.detail||j.error)) ? (j.detail||j.error) : (raw||`HTTP ${r.status}`))
  if(!j) throw new Error(`Unexpected response (not JSON): ${raw.slice(0,200)}`)
  return j
}
async function apiMaximoQuery(payload) {
  const r = await fetch('/api/maximo/query', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(payload) })
  const raw = await r.text()
  let j=null; try{ j=JSON.parse(raw) }catch{}
  if(!r.ok) throw new Error((j && (j.detail||j.error)) ? (j.detail||j.error) : (raw||`HTTP ${r.status}`))
  if(!j) throw new Error(`Unexpected response (not JSON): ${raw.slice(0,200)}`)
  return j
}

function usePrefersDark() {
  const [pref, setPref] = useState(false)
  useEffect(() => {
    const mq = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)')
    if (!mq) return
    const on = () => setPref(!!mq.matches)
    on()
    mq.addEventListener?.('change', on)
    return () => mq.removeEventListener?.('change', on)
  }, [])
  return pref
}

function normalizeTable(table) {
  const columns = Array.isArray(table?.columns) ? table.columns.map(String) : []
  const rows = Array.isArray(table?.rows) ? table.rows : []
  const headers = columns.map((c) => ({ key: c.toLowerCase(), header: c.toUpperCase(), raw: c }))

  const toVal = (r, c) => {
    if (!r) return ''
    const direct = r[c] ?? r[c.toLowerCase()] ?? r[c.toUpperCase()]
    if (direct !== undefined) return direct
    const lc = c.toLowerCase()
    for (const k of Object.keys(r)) {
      if (String(k).toLowerCase().endsWith(lc)) return r[k]
    }
    return ''
  }

  const outRows = rows.map((r, i) => {
    const o = { id: String(i) }
    for (const c of columns) o[c.toLowerCase()] = toVal(r, c)
    return o
  })

  return { headers, rows: outRows }
}

function nowStamp() {
  const d = new Date()
  const pad = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}_${pad(d.getHours())}-${pad(d.getMinutes())}-${pad(d.getSeconds())}`
}

function guessOsFromTitle(table) {
  const t = String(table?.title || '').trim()
  const m = t.match(/\b(mxapi[a-z0-9_]+)\b/i)
  return m ? m[1].toLowerCase() : ''
}

function guessOsFromRows(table) {
  const rows = Array.isArray(table?.rows) ? table.rows : []
  const r = rows && rows.length ? rows[0] : null
  if (!r || typeof r !== 'object') return ''
  const has = (k) => Object.prototype.hasOwnProperty.call(r, k)
  if (has('wonum')) return 'mxapiwo'
  if (has('ticketid')) return 'mxapisr'
  if (has('assetnum')) return 'mxapiasset'
  if (has('location')) return 'mxapilocations'
  if (has('pmnum')) return 'mxapipm'
  if (has('jpnum')) return 'mxapijobplan'
  if (has('ponum')) return 'mxapipo'
  if (has('prnum')) return 'mxapipr'
  return ''
}

function toBaseUrl(settings) {
  const base = String(settings?.maximo?.baseUrl || '').trim().replace(/\/+$/, '')
  return base
}

function getDefaultRecordLinkTemplate(os) {
  // These are best-effort defaults. Many Maximo deployments support loadapp deep-links like this.
  // Users can override per OS in Settings.
  const map = {
    mxapiwo: '{baseUrl}/maximo/ui/?event=loadapp&value={id}&app=wotrack',
    mxapisr: '{baseUrl}/maximo/ui/?event=loadapp&value={id}&app=sr',
    mxapiasset: '{baseUrl}/maximo/ui/?event=loadapp&value={id}&app=asset',
    mxapilocations: '{baseUrl}/maximo/ui/?event=loadapp&value={id}&app=locations',
    mxapipo: '{baseUrl}/maximo/ui/?event=loadapp&value={id}&app=po',
    mxapipr: '{baseUrl}/maximo/ui/?event=loadapp&value={id}&app=pr',
    mxapipm: '{baseUrl}/maximo/ui/?event=loadapp&value={id}&app=pm',
    mxapijobplan: '{baseUrl}/maximo/ui/?event=loadapp&value={id}&app=jobplan',
  }
  return map[String(os || '').toLowerCase()] || ''
}

function getDefaultRecordIdField(os) {
  const map = {
    mxapiwo: 'wonum',
    mxapisr: 'ticketid',
    mxapiasset: 'assetnum',
    mxapilocations: 'location',
    mxapipo: 'ponum',
    mxapipr: 'prnum',
    mxapipm: 'pmnum',
    mxapijobplan: 'jpnum',
  }
  return map[String(os || '').toLowerCase()] || ''
}

function buildRecordUrl({ os, row, settings }) {
  const baseUrl = toBaseUrl(settings)
  if (!baseUrl) return ''

  const idField = getDefaultRecordIdField(os)
  const id = (row && (row[idField] ?? row[idField?.toLowerCase()] ?? row[idField?.toUpperCase()]))
  if (!id) return ''

  const overrides = settings?.maximoUi?.recordLinkTemplates || {}
  const tpl = String(overrides[os] || getDefaultRecordLinkTemplate(os) || '').trim()
  if (!tpl) return ''
  const rendered = tpl
    .replaceAll('{baseUrl}', baseUrl)
    .replaceAll('{os}', String(os || ''))
    .replaceAll('{field}', String(idField || ''))
    .replaceAll('{id}', encodeURIComponent(String(id)))

  // Also support templates that reference any returned column, e.g. {wonum}, {assetnum}, {location},
  // including dot-path keys like {item.description}.
  return rendered.replace(/\{([a-zA-Z0-9_.-]+)\}/g, (_m, key) => {
    if (!row) return ''
    const k = String(key)
    const v = (row[k] ?? row[k.toLowerCase()] ?? row[k.toUpperCase()])
    if (v === undefined || v === null) return ''
    try {
      return encodeURIComponent(typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean' ? String(v) : JSON.stringify(v))
    } catch {
      return encodeURIComponent(String(v))
    }
  })
}

function computeReport(table) {
  const columns = Array.isArray(table?.columns) ? table.columns.map(String) : []
  const rows = Array.isArray(table?.rows) ? table.rows : []
  const n = rows.length
  const report = {
    rowCount: n,
    columnCount: columns.length,
    missingByColumn: [],
    topByColumn: {},
    dateRanges: {},
  }
  if (!n || !columns.length) return report

  const pickTop = (col, k=5) => {
    const counts = new Map()
    for (const r of rows) {
      const v = r?.[col]
      const s = v === null || v === undefined ? '' : String(v).trim()
      if (!s) continue
      counts.set(s, (counts.get(s) || 0) + 1)
    }
    const arr = [...counts.entries()].sort((a,b) => b[1]-a[1]).slice(0,k)
    return arr.map(([value,count]) => ({ value, count }))
  }

  for (const c of columns) {
    let missing = 0
    let maybeDate = 0
    let minDate = null
    let maxDate = null
    for (const r of rows) {
      const v = r?.[c]
      if (v === null || v === undefined || String(v).trim() === '') missing++
      // date heuristics
      const s = (v === null || v === undefined) ? '' : String(v)
      const d = new Date(s)
      if (s && !Number.isNaN(d.getTime()) && /date/i.test(c)) {
        maybeDate++
        if (!minDate || d < minDate) minDate = d
        if (!maxDate || d > maxDate) maxDate = d
      }
    }
    report.missingByColumn.push({ column: c, missing, pct: n ? Math.round((missing/n)*100) : 0 })
    if (['status','siteid','orgid','priority','worktype','class','assettype','loctype','type'].includes(c.toLowerCase())) {
      report.topByColumn[c] = pickTop(c, 8)
    }
    if (maybeDate && minDate && maxDate) {
      report.dateRanges[c] = { min: minDate.toISOString(), max: maxDate.toISOString() }
    }
  }
  report.missingByColumn.sort((a,b) => b.missing - a.missing)
  return report
}

function downloadExcel({ table, message, settings }) {
  const columns = Array.isArray(table?.columns) ? table.columns.map(String) : []
  const rows = Array.isArray(table?.rows) ? table.rows : []
  const os = guessOsFromTitle(table)
  const provider = String(message?.provider || settings?.ai?.provider || 'unknown')
  const model = String(message?.model || settings?.ai?.model || '').replace(/[^a-z0-9._-]+/gi, '-')
  const stamp = nowStamp()
  const safeOs = (os || 'results').replace(/[^a-z0-9._-]+/gi, '-')
  const fileName = `${safeOs}__${provider}${model ? '_' + model : ''}__${stamp}.xlsx`

  const data = rows.map((r) => {
    const o = {}
    for (const c of columns) o[c] = r?.[c]
    return o
  })

  const wb = XLSX.utils.book_new()
  const ws = XLSX.utils.json_to_sheet(data)
  XLSX.utils.book_append_sheet(wb, ws, 'Results')

  const report = computeReport(table)
  const meta = [
    { key: 'title', value: String(table?.title || '') },
    { key: 'os', value: os },
    { key: 'provider', value: provider },
    { key: 'model', value: String(message?.model || settings?.ai?.model || '') },
    { key: 'generatedAt', value: new Date().toISOString() },
    { key: 'rows', value: report.rowCount },
    { key: 'columns', value: report.columnCount },
  ]
  XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(meta), 'Query')
  XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet([
    { section: 'missingByColumn', json: JSON.stringify(report.missingByColumn, null, 2) },
    { section: 'topByColumn', json: JSON.stringify(report.topByColumn, null, 2) },
    { section: 'dateRanges', json: JSON.stringify(report.dateRanges, null, 2) },
  ]), 'Report')

  XLSX.writeFile(wb, fileName)
}

function FilterableTable({ table, settings, message }) {
  const nt = useMemo(() => normalizeTable(table), [table])
  const [filters, setFilters] = useState({})
  useEffect(() => setFilters({}), [table?.title])

  const os = useMemo(() => guessOsFromTitle(table) || guessOsFromRows(table), [table?.title, table?.rows])
  const canExcel = !!settings?.results?.enableExcelDownload
  const canOpen = !!settings?.results?.enableOpenInMaximo
  const showReport = !!settings?.results?.showReport
  const report = useMemo(() => (showReport ? computeReport(table) : null), [table, showReport])

  const filteredRows = useMemo(() => {
    const entries = Object.entries(filters).filter(([,v]) => String(v||'').trim() !== '')
    if (!entries.length) return nt.rows
    return nt.rows.filter((r) => {
      for (const [k, v] of entries) {
        const needle = String(v).toLowerCase()
        const hay = String(r?.[k] ?? '').toLowerCase()
        if (!hay.includes(needle)) return false
      }
      return true
    })
  }, [nt.rows, filters])

  return (
    <div className="mx-table-wrap">
      <div className="mx-table-actions">
        {canExcel ? (
          <Button size="sm" kind="secondary" onClick={() => downloadExcel({ table, message, settings })}>
            Download Excel
          </Button>
        ) : null}
        {os ? <Tag type="cool-gray">{os}</Tag> : null}
        {message?.provider ? <Tag type="warm-gray">{String(message.provider)}{message?.model ? ` · ${String(message.model)}` : ''}</Tag> : null}
        {report ? <Tag type="green">Report</Tag> : null}
      </div>
      <DataTable rows={filteredRows} headers={nt.headers} isSortable>
        {({ rows, headers, getHeaderProps, getRowProps, getTableProps }) => (
          <TableContainer title={table?.title || 'Results'} description="">
            <Table {...getTableProps()} size="sm" useZebraStyles>
              <TableHead>
                <TableRow>
                  {headers.map((h) => (
                    <TableHeader key={h.key} {...getHeaderProps({ header: h })}>
                      <div className="mx-th">
                        <div className="mx-th-title">{h.header}</div>
                        <TextInput
                          id={`flt-${h.key}`}
                          labelText=""
                          hideLabel
                          placeholder="filter…"
                          value={filters[h.key] || ''}
                          onChange={(e) => setFilters((p) => ({ ...p, [h.key]: e.target.value }))}
                          size="sm"
                        />
                      </div>
                    </TableHeader>
                  ))}
                  {canOpen ? <TableHeader key="__open" className="mx-th-open">OPEN</TableHeader> : null}
                </TableRow>
              </TableHead>
              <TableBody>
                {rows.map((row) => (
                  <TableRow key={row.id} {...getRowProps({ row })}>
                    {row.cells.map((cell) => (
                      <TableCell key={cell.id} className="mx-td">
                        {cell.value}
                      </TableCell>
                    ))}
                    {canOpen ? (
                      <TableCell className="mx-td">
                        {(() => {
                          const rawRow = Array.isArray(table?.rows) ? table.rows[Number(row.id)] : null
                          const url = buildRecordUrl({ os, row: rawRow, settings })
                          return url ? (
                            <a href={url} target="_blank" rel="noreferrer">↗</a>
                          ) : (
                            <span className="mx-muted">—</span>
                          )
                        })()}
                      </TableCell>
                    ) : null}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </DataTable>

      {report ? (
        <div className="mx-report">
          <div className="mx-report-head">Summary report</div>
          <div className="mx-report-grid">
            <Tile>
              <div className="mx-report-k">Rows</div>
              <div className="mx-report-v">{report.rowCount}</div>
              <div className="mx-report-k">Columns</div>
              <div className="mx-report-v">{report.columnCount}</div>
            </Tile>
            <Tile>
              <div className="mx-report-k">Most missing columns</div>
              <div className="mx-report-small">
                {report.missingByColumn.slice(0, 5).map((x) => (
                  <div key={x.column} className="mx-report-row">
                    <span>{x.column}</span>
                    <span>{x.pct}% empty</span>
                  </div>
                ))}
              </div>
            </Tile>
          </div>

          {Object.keys(report.topByColumn || {}).length ? (
            <div className="mx-report-top">
              {Object.entries(report.topByColumn).map(([col, items]) => (
                <Tile key={col} className="mx-report-tile">
                  <div className="mx-report-k">Top {col}</div>
                  <div className="mx-report-small">
                    {(items || []).slice(0, 8).map((it) => (
                      <div key={it.value} className="mx-report-row">
                        <span>{it.value}</span>
                        <span>{it.count}</span>
                      </div>
                    ))}
                  </div>
                </Tile>
              ))}
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  )
}


function getAvatarForMessage(m, settings) {
  const avatars = settings?.avatars || {}
  const fallback = String(avatars.default || '').trim()
  if (m?.role === 'user') return String(avatars.user || fallback || '').trim()
  if (m?.role === 'assistant' && m?.source === 'ai') {
    const prov = String(m?.provider || settings?.ai?.provider || '').trim()
    return String((prov && avatars[prov]) || fallback || '').trim()
  }
  return ''
}

function avatarFallbackText(m) {
  if (m?.role === 'user') return 'Y'
  if (m?.source === 'maximo') return 'M'
  const p = String(m?.provider || '').trim()
  return (p ? p[0] : 'A').toUpperCase()
}

function ChatPane({ messages, settings, onOpenTrace }) {
  const bottomRef = useRef(null)
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior:'smooth' }) }, [messages.length])

  return (
    <div className="mx-chat-scroll">
      {messages.map((m, idx) => (
        <div key={idx} className={`mx-msg ${m.role === 'user' ? 'mx-msg-user' : 'mx-msg-assistant'}`}>
          <div className="mx-msg-head">
            {m.role !== 'user' ? (() => {
              const url = getAvatarForMessage(m, settings)
              if (url && isLikelyImageUrl(url)) {
                return <img className="mx-msg-avatar" src={url} alt="" />
              }
              return <div className="mx-msg-avatar mx-msg-avatar-fallback">{avatarFallbackText(m)}</div>
            })() : null}

            <Tag type={m.source === 'maximo' ? 'green' : (m.role === 'assistant' ? 'cool-gray' : 'blue')}>
              {m.source === 'maximo' ? 'Maximo' : (m.role === 'assistant' ? 'AI Agent' : 'You')}
            </Tag>
            {m.intent ? <Tag type="warm-gray">{m.intent}</Tag> : null}
            {m.trace ? <Button size="sm" kind="ghost" onClick={() => onOpenTrace(m.trace)}>Trace</Button> : null}
            {m.role === 'user' ? (() => {
              const url = getAvatarForMessage(m, settings)
              if (url && isLikelyImageUrl(url)) {
                return <img className="mx-msg-avatar" src={url} alt="" />
              }
              return <div className="mx-msg-avatar mx-msg-avatar-fallback">{avatarFallbackText(m)}</div>
            })() : null}
          </div>
          {/* Show assistant text only when there is no table. Keep user text always. */}
          {!(m.role === 'assistant' && m.table) ? (
            <div className="mx-msg-body">{m.text}</div>
          ) : null}
          {m.table ? <FilterableTable table={m.table} settings={settings} message={m} /> : null}
        </div>
      ))}
      <div ref={bottomRef} />
    </div>
  )
}

function PromptBar({ input, setInput, busy, onSend, onClear }) {
  return (
    <div className="mx-promptbar">
      <TextArea
        labelText=""
        hideLabel
        placeholder="Type a message…"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); onSend() } }}
        className="mx-prompt"
      />
      <div className="mx-prompt-actions">
        <Button onClick={onSend} disabled={busy || !input.trim()}>Send</Button>
        <Button kind="danger--tertiary" onClick={onClear} disabled={busy}>Clear</Button>
      </div>
    </div>
  )
}

function PromptChips({ onPick }) {
  return (
    <div className="mx-chips">
      <div className="mx-chips-title">Predefined prompts</div>
      <div className="mx-chips-row">
        {PROMPTS.map((p) => (
          <Button
            key={p.id}
            size="sm"
            kind={p.kind === "danger" ? "danger--tertiary" : "tertiary"}
            className="mx-chip"
            onClick={() => onPick(p)}
          >
            {p.label}
          </Button>
        ))}
      </div>
    </div>
  )
}

function SettingsBody({ local, setLocal, onSave, darkMode, setDarkMode, showSaveButton=true }) {
  const [availableModels, setAvailableModels] = useState([])
  const [modelsWarning, setModelsWarning] = useState('')
  const [linkTplText, setLinkTplText] = useState('')
  const [linkTplWarning, setLinkTplWarning] = useState('')

  const selectedProvider = String(local?.ai?.provider || 'openai')
  const modelItems = useMemo(
    () => (availableModels || []).map((m) => ({ id: m, label: m })),
    [availableModels]
  )
  const selectedModelItem = useMemo(() => {
    const cur = String(local?.ai?.model || '').trim()
    return modelItems.find((it) => it.id === cur) || (cur ? { id: cur, label: cur } : null)
  }, [modelItems, local?.ai?.model])

  // Keep a JSON editor view of record link templates.
  useEffect(() => {
    try {
      setLinkTplWarning('')
      const obj = local?.maximoUi?.recordLinkTemplates || {}
      setLinkTplText(JSON.stringify(obj, null, 2))
    } catch {
      setLinkTplText('{}')
    }
  }, [local?.maximoUi?.recordLinkTemplates])

  // Fetch models whenever the provider changes (best-effort; server returns curated fallbacks).
  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        setModelsWarning('')
        const r = await fetch(`/api/models?provider=${encodeURIComponent(selectedProvider)}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ provider: selectedProvider, settings: local })
        })
        const raw = await r.text()
        let j = null
        try { j = JSON.parse(raw) } catch { j = null }
        const models = Array.isArray(j?.models) ? j.models : []
        if (!cancelled) {
          setAvailableModels(models)
          setModelsWarning(String(j?.warning || ''))
          // If the currently selected model isn't in the list, pick the first one (or keep current).
          const cur = String(local?.ai?.model || '').trim()
          if (models.length && cur && !models.includes(cur)) {
            setLocal((p) => ({ ...p, ai: { ...(p.ai || {}), model: models[0] } }))
          }
          if (models.length && !cur) {
            setLocal((p) => ({ ...p, ai: { ...(p.ai || {}), model: models[0] } }))
          }
        }
      } catch (e) {
        if (!cancelled) {
          setAvailableModels([])
          setModelsWarning(String(e?.message || e))
        }
      }
    })()
    return () => { cancelled = true }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedProvider])

  // Keep link template editor text in sync with current settings.
  useEffect(() => {
    try {
      const obj = local?.maximoUi?.recordLinkTemplates || {}
      setLinkTplText(JSON.stringify(obj, null, 2))
      setLinkTplWarning('')
    } catch {
      setLinkTplText('{}')
    }
  }, [local?.maximoUi?.recordLinkTemplates])

  return (
    <div className="mx-page">
      <h2 className="mx-h2">Settings</h2>
      <p className="mx-muted">All settings are stored in your browser local storage.</p>

      <div className="mx-card">
        <h3 className="mx-h3">Appearance</h3>
        <div className="mx-form">
          <Toggle
            id="ui-darkmode"
            labelText="Dark mode (pages only)"
            toggled={!!darkMode}
            onToggle={(v) => setDarkMode(!!v)}
          />
          <p className="mx-muted" style={{ marginTop: 0 }}>
            The header and navigation pane always use a fixed black background and white foreground.
          </p>
        </div>
      </div>

      <div className="mx-card">
        <h3 className="mx-h3">Results & Actions</h3>
        <div className="mx-form">
          <Toggle
            id="res-report"
            labelText="Show summary report under tables"
            toggled={!!local?.results?.showReport}
            onToggle={(v) => setLocal((p) => ({ ...p, results: { ...(p.results||{}), showReport: !!v } }))}
          />
          <Toggle
            id="res-excel"
            labelText="Enable Download Excel button"
            toggled={!!local?.results?.enableExcelDownload}
            onToggle={(v) => setLocal((p) => ({ ...p, results: { ...(p.results||{}), enableExcelDownload: !!v } }))}
          />
          <Toggle
            id="res-open"
            labelText="Enable Open-in-Maximo links per row"
            toggled={!!local?.results?.enableOpenInMaximo}
            onToggle={(v) => setLocal((p) => ({ ...p, results: { ...(p.results||{}), enableOpenInMaximo: !!v } }))}
          />
        </div>
        <p className="mx-muted" style={{ marginTop: '0.5rem' }}>
          "Open in Maximo" uses a per-Object-Structure link template. Defaults are best-effort and may vary by tenant.
        </p>
        <TextArea
          id="mx-link-templates"
          labelText="Record link templates (JSON; optional)"
          rows={8}
          value={linkTplText}
          onChange={(e) => {
            const txt = e.target.value
            setLinkTplText(txt)
            try {
              const parsed = JSON.parse(txt || '{}')
              setLinkTplWarning('')
              setLocal((p) => ({ ...p, maximoUi: { ...(p.maximoUi||{}), recordLinkTemplates: parsed } }))
            } catch {
              setLinkTplWarning('Invalid JSON (changes not applied yet).')
            }
          }}
        />
        {linkTplWarning ? <InlineNotification kind="warning" lowContrast title="Record links" subtitle={linkTplWarning} /> : null}
        <p className="mx-muted" style={{ marginTop: '0.5rem' }}>
          Template placeholders: <code>{'{baseUrl}'}</code> <code>{'{os}'}</code> <code>{'{field}'}</code> <code>{'{id}'}</code>.
        </p>
      </div>


<div className="mx-card">
        <h3 className="mx-h3">Maximo</h3>
        <div className="mx-form">
          <TextInput id="mx-base-p" labelText="Maximo Base URL" value={local?.maximo?.baseUrl || ''}
            onChange={(e) => setLocal((p) => ({ ...p, maximo:{ ...(p.maximo||{}), baseUrl:e.target.value } }))} />
          <TextInput id="mx-key-p" labelText="Maximo API Key" type="password" value={local?.maximo?.apiKey || ''}
            onChange={(e) => setLocal((p) => ({ ...p, maximo:{ ...(p.maximo||{}), apiKey:e.target.value } }))} />
          <TextInput id="mx-site-p" labelText="Default Site" value={local?.maximo?.defaultSite || ''}
            onChange={(e) => setLocal((p) => ({ ...p, maximo:{ ...(p.maximo||{}), defaultSite:e.target.value } }))} />
          <TextInput id="mx-tenant-p" labelText="Default Tenant" value={local?.maximo?.defaultTenant || 'default'}
            onChange={(e) => setLocal((p) => ({ ...p, maximo:{ ...(p.maximo||{}), defaultTenant:e.target.value } }))} />
        </div>
      </div>

      <div className="mx-card">
        <h3 className="mx-h3">MCP Tool Orchestration</h3>
        <div className="mx-form">
          <Toggle id="mcp-enable-p" labelText="Enable MCP tool orchestration" toggled={!!local?.mcp?.enableTools}
            onToggle={(v) => setLocal((p) => ({ ...p, mcp:{ ...(p.mcp||{}), enableTools: !!v } }))} />
          <TextInput id="mcp-url-p" labelText="MCP Server URL" value={local?.mcp?.url || ''}
            onChange={(e) => setLocal((p) => ({ ...p, mcp:{ ...(p.mcp||{}), url:e.target.value } }))} />
        </div>
      </div>

      <div className="mx-card">
        <h3 className="mx-h3">AI Provider</h3>
        <div className="mx-form">
          <Dropdown
            id="ai-provider-dd"
            titleText="Provider"
            label=""
            items={PROVIDERS}
            itemToString={(it) => (it ? it.label : '')}
            selectedItem={PROVIDERS.find(p => p.id === (local?.ai?.provider || 'openai')) || PROVIDERS[0]}
            onChange={({ selectedItem }) => setLocal((p) => ({ ...p, ai:{ ...(p.ai||{}), provider:(selectedItem?.id || 'openai') } }))}
          />
          <Dropdown
            id="ai-model-dd"
            titleText="Model"
            label=""
            items={modelItems}
            itemToString={(it) => (it ? it.label : '')}
            selectedItem={selectedModelItem}
            onChange={({ selectedItem }) => setLocal((p) => ({ ...p, ai:{ ...(p.ai||{}), model:(selectedItem?.id || '') } }))}
          />
          {modelsWarning ? (
            <InlineNotification kind="warning" lowContrast title="Model list" subtitle={modelsWarning} />
          ) : null}
          <TextArea
            id="ai-system-p"
            labelText="System prompt"
            rows={6}
            value={local?.ai?.system || ''}
            onChange={(e) => setLocal((p) => ({ ...p, ai:{ ...(p.ai||{}), system:e.target.value } }))}
          />
        </div>
        <p className="mx-muted" style={{ marginTop: '0.5rem' }}>
          Tip: set an avatar per provider in the section below.
        </p>
      </div>

      <div className="mx-card">
        <h3 className="mx-h3">Avatars (optional)</h3>
        <p className="mx-muted" style={{ marginTop: 0 }}>
          Paste a <code>data:</code> URL, a normal image URL, or a website URL (we'll show its favicon).
        </p>
        <div className="mx-form">
          {[
            { key:'default', label:'Global default' },
            { key:'openai', label:'OpenAI' },
            { key:'anthropic', label:'Anthropic' },
            { key:'gemini', label:'Gemini' },
            { key:'watsonx', label:'IBM watsonx' },
            { key:'mistral', label:'Mistral' },
            { key:'deepseek', label:'DeepSeek' },
            { key:'user', label:'User' },
          ].map((row) => {
            const v = (local?.avatars?.[row.key] || '').trim()
            return (
              <div key={row.key} className="mx-ava-row">
                <div className="mx-ava-label">{row.label}</div>
                <TextInput
                  id={`ava-${row.key}`}
                  labelText=""
                  value={v}
                  placeholder={row.key === 'default' || row.key === 'user' ? 'data:… or URL' : ''}
                  onChange={(e) => setLocal((p) => ({ ...p, avatars:{ ...(p.avatars||{}), [row.key]: e.target.value } }))}
                />
                <div className="mx-ava-preview">
                  {v ? <img src={resolveAvatarSrc(v)} alt={`${row.key} avatar`} /> : <div className="mx-ava-fallback">{row.key === 'user' ? 'U' : 'AI'}</div>}
                </div>
              </div>
            )
          })}
        </div>
      </div>
      {showSaveButton ? (
        <div style={{ display:'flex', gap:'0.5rem', marginTop:'1rem' }}>
          <Button onClick={onSave}>Save settings</Button>
        </div>
      ) : null}
    </div>
  )
}


function SettingsDialog({ open, onClose, settings, setSettings, darkMode, setDarkMode }) {
  const [local, setLocal] = useState(settings)
  useEffect(() => { if(open) setLocal(settings) }, [open])

  const save = () => {
    setSettings(local)
    persistSettings(local)
  }

  const saveAndClose = () => {
    save()
    onClose()
  }

  return (
    <Modal
      open={open}
      onRequestClose={saveAndClose}
      modalHeading="Settings"
      primaryButtonText="Save & Close"
      onRequestSubmit={saveAndClose}
      size="lg"
      className="mx-settings-modal"
    >
      <SettingsBody
        local={local}
        setLocal={setLocal}
        onSave={save}
        darkMode={darkMode}
        setDarkMode={setDarkMode}
        showSaveButton={true}
      />
    </Modal>
  )
}


function SettingsPage({ settings, setSettings, darkMode, setDarkMode }) {
  const [local, setLocal] = useState(settings)
  useEffect(() => setLocal(settings), [settings])
  const save = () => { setSettings(local); persistSettings(local) }

  return (
    <SettingsBody
      local={local}
      setLocal={setLocal}
      onSave={save}
      darkMode={darkMode}
      setDarkMode={setDarkMode}
      showSaveButton={true}
    />
  )
}


function HelpModal({ open, onClose }) {
  const [html, setHtml] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    if (!open) return
    let cancelled = false
    ;(async () => {
      try {
        setError('')
        const res = await fetch('/help.html', { cache: 'no-cache' })
        if (!res.ok) throw new Error(`Unable to load help content (HTTP ${res.status})`)
        const t = await res.text()
        if (!cancelled) setHtml(t)
      } catch (e) {
        if (!cancelled) setError(e?.message || String(e))
      }
    })()
    return () => { cancelled = true }
  }, [open])

  return (
    <Modal
      open={open}
      modalHeading="Help"
      primaryButtonText="Close"
      onRequestClose={onClose}
      onRequestSubmit={onClose}
      size="lg"
    >
      {error ? (
        <InlineNotification kind="error" lowContrast title="Help unavailable" subtitle={error} hideCloseButton />
      ) : (
        <div className="mx-help-content" dangerouslySetInnerHTML={{ __html: html }} />
      )}
    </Modal>
  )
}

function Layout({ children, darkMode, setDarkMode, navExpanded, setNavExpanded }) {
  const nav = useNavigate()
  const loc = useLocation()
  const theme = darkMode ? 'g100' : 'white'
  const navW = navExpanded ? NAV_EXPANDED_W : NAV_COLLAPSED_W
  const [helpOpen, setHelpOpen] = useState(false)

  return (
    <Theme theme={theme}>
      <div className="mx-root">
        <Header aria-label="Maximo AI Agent" className="mx-header">
          <HeaderGlobalAction aria-label="Toggle navigation" onClick={() => setNavExpanded((v)=>!v)}>
            <Menu />
          </HeaderGlobalAction>
          <HeaderName prefix="" onClick={() => nav('/chat')} style={{ cursor:'pointer' }}>
            Maximo AI Agent
          </HeaderName>
          <HeaderGlobalBar>
            <HeaderGlobalAction aria-label="Settings (dialog)" onClick={() => window.dispatchEvent(new CustomEvent('mx-open-settings'))}>
              <Settings />
            </HeaderGlobalAction>
            
            <HeaderGlobalAction aria-label="Help" onClick={() => setHelpOpen(true)}>
              <Information />
            </HeaderGlobalAction>
<HeaderGlobalAction
              aria-label="Logout"
              onClick={async () => {
                try {
                  await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' })
                } finally {
                  window.location.reload()
                }
              }}
            >
              <Logout />
            </HeaderGlobalAction>
          </HeaderGlobalBar>
        </Header>

        <HelpModal open={helpOpen} onClose={() => setHelpOpen(false)} />

        <div className="mx-body">
          <div className="mx-sidenav" style={{ width: navW }}>
            <SideNav isFixedNav expanded={navExpanded} isChildOfHeader aria-label="Side navigation" className="mx-sidenav-inner">
              <SideNavItems>
                <SideNavLink
                  href="/chat"
                  isActive={loc.pathname.startsWith('/chat')}
                  onClick={(e) => {
                    e.preventDefault()
                    nav('/chat')
                  }}
                >
                  <Chat /> {navExpanded ? 'Chat' : ''}
                </SideNavLink>
                <SideNavLink
                  href="/settings"
                  isActive={loc.pathname.startsWith('/settings')}
                  onClick={(e) => {
                    e.preventDefault()
                    nav('/settings')
                  }}
                >
                  <Settings /> {navExpanded ? 'Settings' : ''}
                </SideNavLink>
              </SideNavItems>

              <div className="mx-sidenav-footer">
                <Toggle id="theme-toggle" labelText="" labelA="Light" labelB="Dark" toggled={darkMode} onToggle={(v)=>setDarkMode(!!v)} />
              </div>
            </SideNav>
          </div>

          <Content className="mx-content" style={{ marginLeft: navW }}>
            {children}
          </Content>
        </div>
      </div>
    </Theme>
  )
}

function ChatPage({ settings, mode, setMode }) {
  const LAST_TOOL_RESULT_KEY = 'mx_last_tool_result'
  const [messages, setMessages] = useState(() => {
    try {
      const raw = sessionStorage.getItem(CHAT_STORAGE_KEY)
      if (!raw) return []
      const parsed = JSON.parse(raw)
      return Array.isArray(parsed?.messages) ? parsed.messages : []
    } catch { return [] }
  })
  const [input, setInput] = useState(() => {
    try {
      const raw = sessionStorage.getItem(CHAT_STORAGE_KEY)
      if (!raw) return ''
      const parsed = JSON.parse(raw)
      return String(parsed?.draft || '')
    } catch { return '' }
  })
  const [busy, setBusy] = useState(false)
  const [traceOpen, setTraceOpen] = useState(false)
  const [traceData, setTraceData] = useState(null)

  // Guided modal: Create WO/SR
  const [createOpen, setCreateOpen] = useState(false)
  const [createType, setCreateType] = useState('wo')
  const [createTenant, setCreateTenant] = useState(() => String(settings?.maximo?.defaultTenant || 'default'))
  const [createSite, setCreateSite] = useState(() => String(settings?.maximo?.defaultSite || '').trim().toUpperCase())
  const [createPriority, setCreatePriority] = useState('3')
  const [createDesc, setCreateDesc] = useState('')
  const [createAsset, setCreateAsset] = useState('')
  const [assetItems, setAssetItems] = useState([])
  const [assetsBusy, setAssetsBusy] = useState(false)
  const [tenantItems, setTenantItems] = useState([])
  const [tenantsBusy, setTenantsBusy] = useState(false)
  const [tenantsError, setTenantsError] = useState('')

  const openCreate = async (type) => {
    setCreateType(type)
    setCreateTenant(String(settings?.maximo?.defaultTenant || 'default'))
    setCreateSite(String(settings?.maximo?.defaultSite || '').trim().toUpperCase())
    setCreatePriority('3')
    setCreateDesc('')
    setCreateAsset('')
    setAssetItems([])
    setCreateOpen(true)
  }

  // Load tenant value list when the create modal opens
  useEffect(() => {
    if (!createOpen) return
    let cancelled = false
    ;(async () => {
      try {
        setTenantsError('')
        setTenantsBusy(true)
        const resp = await apiValueListTenants({ settings })
        const unwrapped = resp?.content?.[0]?.text ? safeJsonParse(resp.content[0].text) : resp
        const list = Array.isArray(unwrapped?.tenants) ? unwrapped.tenants : []
        if (!cancelled) setTenantItems(list)
        if (!cancelled && list.length) {
          // If the current tenant isn't in the list, default to the first tenant.
          if (!list.includes(createTenant)) setCreateTenant(String(list[0] || 'default'))
        }
      } catch (e) {
        if (!cancelled) {
          setTenantItems([])
          setTenantsError(String(e?.message || e))
        }
      } finally {
        if (!cancelled) setTenantsBusy(false)
      }
    })()
    return () => { cancelled = true }
  }, [createOpen])

  // Load assets value list whenever the modal is open and site/tenant changes
  useEffect(() => {
    if (!createOpen) return
    if (!createSite) return
    let cancelled = false
    ;(async () => {
      try {
        setAssetsBusy(true)
        const resp = await apiValueListAssets({ settings, tenant: createTenant, site: createSite, pageSize: 120 })
        const unwrapped = resp?.content?.[0]?.text ? safeJsonParse(resp.content[0].text) : resp
        const items = unwrapped?.items || []
        if (!cancelled) setAssetItems(items)
      } catch {
        if (!cancelled) setAssetItems([])
      } finally {
        if (!cancelled) setAssetsBusy(false)
      }
    })()
    return () => { cancelled = true }
  }, [createOpen, createTenant, createSite])

  useEffect(() => {
    try {
      sessionStorage.setItem(CHAT_STORAGE_KEY, JSON.stringify({ messages, draft: input }))
    } catch {}
  }, [messages, input])

  const openTrace = (t) => { setTraceData(t); setTraceOpen(true) }
  const clearChat = () => { setMessages([]); setInput(''); try { sessionStorage.removeItem(CHAT_STORAGE_KEY) } catch {} }

  const send = async (forced) => {
    const text = String(forced ?? input).trim()
    const defaultSite = String(settings?.maximo?.defaultSite || '').trim().toUpperCase()
    const textForMaximo = (defaultSite && !/\bsiteid\s*=\s*/i.test(text)) ? `${text} siteid = ${defaultSite}` : text
    const systemForAI = `${String(settings?.ai?.system || '')}${defaultSite ? `

Default Maximo siteid: ${defaultSite}.` : ''}

When users ask for Preventive Maintenance (PMs), call MCP tool maximo_queryOS with os set to mxapipm.
When users ask for Job Plans, call MCP tool maximo_queryOS with os set to mxapijobplan.`.trim()
    if (!text) return
    setBusy(true)
    setMessages((m) => [...m, { role:'user', text }])
    setInput('')
    try {
      if (mode === 'maximo') {
        const resp = await apiMaximoQuery({ text: textForMaximo, settings })
        setMessages((m) => [...m, { role:'assistant', source:'maximo', text: resp.summary || 'OK', table: resp.table || null, trace: resp.trace || null , provider:'maximo', model:'' }])
      } else {
        const resp = await apiAgentChat({
          provider: settings?.ai?.provider || 'openai',
          model: settings?.ai?.model || '',
          system: systemForAI,
          temperature: settings?.ai?.temperature ?? 0.7,
          text,
          settings
        })
        // Store last tool result (if present) for "Analyze / Summarize last response"
        try {
          if (resp && resp.lastToolResult != null) localStorage.setItem(LAST_TOOL_RESULT_KEY, JSON.stringify(resp.lastToolResult))
        } catch {}
        // ✅ UPDATED (minimal): attach resp.table so AI Agent mode renders the same table view
        let assistantText = (resp && (resp.reply ?? resp.text)) ?? (resp && resp.error ? `Error: ${resp.detail || resp.error}` : '');
      if (!assistantText && resp && typeof resp === 'object') {
        try { assistantText = JSON.stringify(resp, null, 2); } catch {}
      }
      setMessages((m) => [...m, { role:'assistant', source:'ai', provider: settings?.ai?.provider || 'openai', model: settings?.ai?.model || '',  text: assistantText, table: resp?.table || null, trace: resp?.trace || null }])
      }
    } catch (e) {
      setMessages((m) => [...m, { role:'assistant', source: mode==='maximo' ? 'maximo' : 'ai', text: `Error: ${String(e.message || e)}` }])
    } finally {
      setBusy(false)
    }
  }

  const pickPrompt = async (p) => {
    if (p?.action === "create_wo") return openCreate("wo")
    if (p?.action === "create_sr") return openCreate("sr")
    if (p?.action === "analyze_last") {
      try {
        const raw = localStorage.getItem(LAST_TOOL_RESULT_KEY)
        if (!raw) {
          setMessages((m) => [...m, { role:'assistant', source:'ai', provider: settings?.ai?.provider || 'openai', model: settings?.ai?.model || '', text: "No previous tool response found yet. Run a tool-based prompt first." }])
          return
        }
        const lastToolResult = safeJsonParse(raw) || raw
        setBusy(true)
        setMessages((m) => [...m, { role:'user', text: "Analyze / Summarize last response" }])
        const systemForAI = String(settings?.ai?.system || '').trim()
        const resp = await apiAnalyzeLast({ provider: settings?.ai?.provider || 'openai', model: settings?.ai?.model || '', system: systemForAI, temperature: Math.min(0.4, Number(settings?.ai?.temperature ?? 0.2)), lastToolResult, settings })
        setMessages((m) => [...m, { role:'assistant', source:'ai', provider: settings?.ai?.provider || 'openai', model: settings?.ai?.model || '', text: resp?.reply || '' }])
      } catch (e) {
        setMessages((m) => [...m, { role:'assistant', source:'ai', provider: settings?.ai?.provider || 'openai', model: settings?.ai?.model || '', text: `Error: ${String(e?.message || e)}` }])
      } finally {
        setBusy(false)
      }
      return
    }
    return send(p.prompt)
  }

  return (
    <div className="mx-chat-page">
      <div className="mx-chat-toolbar">
        <Dropdown
          id="mode"
          titleText="Mode"
          label=""
          items={[{ id:'maximo', label:'Maximo Mode' }, { id:'ai', label:'AI Agent Mode' }]}
          itemToString={(i)=>i?.label||''}
          selectedItem={{ id: mode, label: mode === 'maximo' ? 'Maximo Mode' : 'AI Agent Mode' }}
          onChange={({ selectedItem }) => setMode(selectedItem?.id || 'maximo')}
        />
        {mode === 'maximo'
          ? <Tag type="green">siteid={String(settings?.maximo?.defaultSite || '').toUpperCase() || '—'}</Tag>
          : <Tag type="cool-gray">{(settings?.ai?.provider || 'openai') + (settings?.ai?.model ? ` · ${settings.ai.model}` : '')}</Tag>}
      </div>

      <div className="mx-chat-card">
        <ChatPane messages={messages} settings={settings} onOpenTrace={openTrace} />
        <PromptBar input={input} setInput={setInput} busy={busy} onSend={() => send()} onClear={clearChat} />
      </div>

      <PromptChips onPick={pickPrompt} />

      <Modal
        open={createOpen}
        onRequestClose={() => setCreateOpen(false)}
        modalHeading={createType === 'wo' ? 'Create Work Order' : 'Create Service Request'}
        primaryButtonText={createType === 'wo' ? 'Create WO' : 'Create SR'}
        secondaryButtonText="Cancel"
        size="md"
        onRequestSubmit={async () => {
          try {
            const site = String(createSite || '').trim().toUpperCase()
            const description = String(createDesc || '').trim()
            const priority = String(createPriority || '').trim()
            const assetnum = String(createAsset || '').trim()

            const label = createType === 'wo' ? 'Work Order' : 'Service Request'
            setMessages((m) => [...m, { role:'user', text: `Create ${label} (tenant ${createTenant}, site ${site}): ${description}` }])

            setBusy(true)
            const resp = await apiCreateRecord({
              settings,
              type: createType,
              tenant: createTenant,
              site,
              assetnum: assetnum || undefined,
              priority: priority || undefined,
              description,
            })

            const id = String(resp?.id || resp?.response?.id || '')
            const os = String(resp?.response?.os || (createType === 'wo' ? 'mxapiwo' : 'mxapisr'))

            // Keep a local copy for the "Analyze / Summarize last response" prompt.
            try { localStorage.setItem(LAST_TOOL_RESULT_KEY, JSON.stringify(resp?.response || resp)) } catch {}

            const columns = createType === 'wo'
              ? ['wonum','description','siteid','assetnum','priority']
              : ['ticketid','description','siteid','assetnum','priority']
            const row = createType === 'wo'
              ? { wonum: id, description, siteid: site, assetnum: assetnum || '', priority: priority || '' }
              : { ticketid: id, description, siteid: site, assetnum: assetnum || '', priority: priority || '' }
            const table = id ? { title: os, columns, rows: [row] } : null

            setMessages((m) => [...m, {
              role:'assistant',
              source:'maximo',
              provider:'mcp',
              model:'',
              text: id ? `Created ${label} ${id}.` : `Created ${label}.`,
              table,
              trace: resp?.response || resp || null
            }])
            setCreateOpen(false)
          } catch (e) {
            setMessages((m) => [...m, { role:'assistant', source:'maximo', text: `Error: ${String(e?.message || e)}` }])
          } finally {
            setBusy(false)
          }
        }}
      >
        <Stack gap={5}>
          {tenantsError ? (
            <InlineNotification kind="warning" lowContrast title="Tenants" subtitle={tenantsError} />
          ) : null}
          <Dropdown
            id="cr-tenant"
            titleText={tenantsBusy ? 'Tenant (loading...)' : 'Tenant'}
            label="Select a tenant"
            items={(tenantItems && tenantItems.length) ? tenantItems : [String(createTenant || 'default')]}
            itemToString={(it) => String(it || '')}
            selectedItem={String(createTenant || 'default')}
            onChange={({ selectedItem }) => setCreateTenant(String(selectedItem || 'default'))}
          />
          <TextInput
            id="cr-site"
            labelText="Site"
            value={createSite}
            onChange={(e) => setCreateSite(String(e.target.value).toUpperCase())}
          />
          <ComboBox
            id="cr-asset"
            titleText={assetsBusy ? 'Asset (loading...)' : 'Asset (optional)'}
            placeholder="Select an asset (optional)"
            items={(assetItems || []).map((it) => ({
              id: String(it.assetnum || it.id || ''),
              label: String(it.label || it.assetnum || it.id || ''),
            })).filter((it) => !!it.id)}
            itemToString={(i) => i?.label || ''}
            selectedItem={(() => {
              const items = (assetItems || []).map((it) => ({
                id: String(it.assetnum || it.id || ''),
                label: String(it.label || it.assetnum || it.id || ''),
              })).filter((it) => !!it.id)
              return items.find((it) => it.id === String(createAsset || '')) || null
            })()}
            onChange={({ selectedItem }) => setCreateAsset(selectedItem?.id || '')}
            disabled={assetsBusy || !createSite}
          />
          <Dropdown
            id="cr-priority"
            titleText="Priority"
            label="Priority"
            items={['1','2','3','4','5']}
            itemToString={(it) => String(it || '')}
            selectedItem={String(createPriority || '3')}
            onChange={({ selectedItem }) => setCreatePriority(String(selectedItem || '3'))}
          />
          <TextArea
            id="cr-desc"
            labelText="Description"
            value={createDesc}
            onChange={(e) => setCreateDesc(e.target.value)}
            rows={4}
          />
        </Stack>
      </Modal>

      <Modal
        open={traceOpen}
        onRequestClose={() => setTraceOpen(false)}
        modalHeading="Trace"
        primaryButtonText="Close"
        onRequestSubmit={() => setTraceOpen(false)}
        size="lg"
      >
        <CodeSnippet type="multi" wrapText hideCopyButton={false}>
          {JSON.stringify(traceData, null, 2)}
        </CodeSnippet>
      </Modal>
    </div>
  )
}

function AppInner() {
  const prefersDark = usePrefersDark()
  const [darkMode, setDarkMode] = useState(() => {
    const saved = localStorage.getItem('agent_ui_dark_v2')
    if (saved === '1') return true
    if (saved === '0') return false
    return prefersDark
  })
  useEffect(() => { localStorage.setItem('agent_ui_dark_v2', darkMode ? '1' : '0') }, [darkMode])

  const [navExpanded, setNavExpanded] = useState(true)

  const [settings, setSettings] = useState(() => loadSettings() || {
    mode: 'maximo',
    maximo: { baseUrl:'', apiKey:'', defaultSite:'', defaultTenant:'default' },
    ai: { provider:'openai', model:'gpt-4o-mini', system:'', temperature:0.7 },
    mcp: { enableTools:false, url:'' },
    avatars: {
      default: '',
      user: '',
      openai: '',
      anthropic: '',
      gemini: '',
      watsonx: '',
      mistral: '',
      deepseek: ''
    }
  })
  useEffect(() => persistSettings(settings), [settings])

  const [mode, setMode] = useState(settings.mode || 'maximo')
  useEffect(() => setSettings((p) => ({ ...p, mode })), [mode])

  const [settingsDialog, setSettingsDialog] = useState(false)
  useEffect(() => {
    const onOpen = () => setSettingsDialog(true)
    window.addEventListener('mx-open-settings', onOpen)
    return () => window.removeEventListener('mx-open-settings', onOpen)
  }, [])

  return (
    <Layout darkMode={darkMode} setDarkMode={setDarkMode} navExpanded={navExpanded} setNavExpanded={setNavExpanded}>
      <Routes>
        <Route path="/chat" element={<ChatPage settings={settings} mode={mode} setMode={setMode} />} />
} />
        <Route path="/settings" element={<SettingsPage settings={settings} setSettings={setSettings} darkMode={darkMode} setDarkMode={setDarkMode} />} />        
} />
        <Route path="*" element={<Navigate to="/chat" replace />} />
      </Routes>

      <SettingsDialog open={settingsDialog} onClose={() => setSettingsDialog(false)} settings={settings} setSettings={setSettings} darkMode={darkMode} setDarkMode={setDarkMode} />
    </Layout>
  )
}

export default function AppCore() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Navigate to="/chat" replace />} />
        <Route path="/*" element={<AppInner />} />
      </Routes>
    </BrowserRouter>
  )
}


