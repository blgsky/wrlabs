/*
 * Serves the encrypted site.
 *
 * Every request under /wrlabs/ is answered from an enc/ blob decrypted here,
 * with the key the gate page put in IndexedDB. Without a key the worker steps
 * aside and lets the network answer — which returns the gate, since the only
 * readable files left on the host are the gate, this worker and enc/.
 *
 * Decrypted responses are marked no-store: the ciphertext is what belongs in
 * the browser's disk cache, not the plaintext.
 */

const BASE = new URL('./', self.location).pathname
const ENC = BASE + 'enc/'
const DB_NAME = 'wrlabs-gate'
const STORE = 'key'

self.addEventListener('install', () => self.skipWaiting())
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()))

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1)
    req.onupgradeneeded = () => req.result.createObjectStore(STORE)
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

async function readKey() {
  const db = await openDb()
  const record = await new Promise((resolve, reject) => {
    const req = db.transaction(STORE, 'readonly').objectStore(STORE).get('session')
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
  if (!record) return null
  if (Date.now() > record.expires) {
    const tx = db.transaction(STORE, 'readwrite')
    tx.objectStore(STORE).delete('session')
    return null
  }
  return record.key
}

async function decrypt(key, buffer) {
  const bytes = new Uint8Array(buffer)
  return crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bytes.subarray(0, 12) },
    key,
    bytes.subarray(12)
  )
}

// Held for the worker's lifetime, not the session's: the worker is stopped and
// restarted freely, and each restart re-reads the key from IndexedDB.
let sessionPromise = null

function session() {
  if (!sessionPromise) {
    sessionPromise = (async () => {
      const key = await readKey()
      if (!key) return null
      const response = await fetch(ENC + 'manifest.bin', { cache: 'no-store' })
      if (!response.ok) return null
      const plain = await decrypt(key, await response.arrayBuffer())
      const manifest = JSON.parse(new TextDecoder().decode(plain))
      // Every directory holding an index.html can absorb the SPA routes below
      // it — which is what used to take a 404 page and a redirect.
      const roots = Object.keys(manifest)
        .filter((path) => path.endsWith('index.html'))
        .map((path) => path.slice(0, -'index.html'.length))
        .sort((a, b) => b.length - a.length)
      return { key, manifest, roots }
    })().catch(() => null)
  }
  return sessionPromise
}

function resolve(active, rel) {
  if (rel === '' || rel.endsWith('/')) rel += 'index.html'
  if (active.manifest[rel]) return active.manifest[rel]
  // A path that names a directory without the trailing slash reaches us as a
  // navigation the host would have redirected; there is no host to do it here.
  if (active.manifest[rel + '/index.html']) return active.manifest[rel + '/index.html']
  return null
}

// A dead link inside the site should say so in the site's own voice, and say
// which path died — a bare "Not found" leaves nobody, including whoever has to
// debug it, any way to tell a stray link from a broken worker.
function missing(rel) {
  return new Response(
    '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width,initial-scale=1">' +
      '<meta name="robots" content="noindex, nofollow"><title>Not found</title>' +
      '<style>html{background:#08080c}body{margin:0;min-height:100svh;display:flex;' +
      'align-items:center;justify-content:center;font-family:Montserrat,-apple-system,' +
      'BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:rgba(255,255,255,.62)}' +
      'main{max-width:32rem;padding:2rem;text-align:center}h1{margin:0 0 .75rem;font-size:1.5rem;' +
      'font-weight:600;color:#fff}code{font-size:.85rem;color:rgba(255,255,255,.45);' +
      'word-break:break-all}a{display:inline-block;margin-top:1.5rem;padding:.7rem 1.6rem;' +
      'border-radius:999px;background:#175ad4;color:#fff;text-decoration:none;font-weight:600;' +
      'font-size:.95rem}</style></head><body><main><h1>That page is not here</h1>' +
      '<p><code>' +
      rel.replace(/[<&]/g, (c) => (c === '<' ? '&lt;' : '&amp;')) +
      '</code></p><a href="' +
      BASE +
      '">Back to the demos</a></main></body></html>',
    {
      status: 404,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Robots-Tag': 'noindex, nofollow',
      },
    }
  )
}

function spaFallback(active, rel) {
  const root = active.roots.find((prefix) => rel.startsWith(prefix))
  return root === undefined ? null : active.manifest[root + 'index.html']
}

async function handle(request, url) {
  const active = await session()
  // No key, or a key that no longer decrypts this build: let the gate answer.
  if (!active) return fetch(request)

  const rel = decodeURIComponent(url.pathname.slice(BASE.length))
  // Anything that is not plainly an asset request is treated as a page, so a
  // route lands on its app rather than a dead end. Browsers disagree about what
  // `mode` a navigation carries, and guessing wrong here is what turns a
  // working deep link into a broken one.
  const isPage = request.mode === 'navigate' || !/\.[a-z0-9]+$/i.test(rel)
  // A missing asset gets an empty 404, never the page below: handing HTML to
  // something that asked for a script only turns a 404 into a parse error.
  const dead = () => (isPage ? missing(rel) : new Response(null, { status: 404 }))

  const entry = resolve(active, rel) || (isPage ? spaFallback(active, rel) : null)
  if (!entry) return dead()

  const sealed = await fetch(ENC + entry.i + '.bin')
  if (!sealed.ok) return dead()

  try {
    const plain = await decrypt(active.key, await sealed.arrayBuffer())
    return new Response(plain, {
      headers: {
        'Content-Type': entry.t,
        'Cache-Control': 'no-store',
        'X-Robots-Tag': 'noindex, nofollow',
      },
    })
  } catch {
    // A stale key against a rebuilt site: drop it and fall back to the gate.
    sessionPromise = null
    return fetch(request)
  }
}

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url)
  if (url.origin !== self.location.origin) return
  if (!url.pathname.startsWith(BASE)) return
  // The gate and the sealed blobs must stay reachable as themselves.
  if (url.pathname === BASE + 'sw.js') return
  if (url.pathname.startsWith(ENC)) return

  event.respondWith(handle(event.request, url))
})

// The gate signals a fresh unlock; drop the memoised session so the next
// request re-reads the new key instead of the absent one.
self.addEventListener('message', (event) => {
  if (event.data === 'unlocked') sessionPromise = null
})
