// Writes and checks installer/output/manifest.json, the file the VS Code extension reads
// (vigil-vscode/src/backendManager.ts: win_x64.url and win_x64.sha256) to find and verify the installer.
// This only writes a build output next to the installer. Nothing is uploaded or published here.
//
//   node manifest.js write <installer.exe> <version> [<manifest.json>]
//   node manifest.js check <manifest.json> <installer.exe> <version>
//
// check fails (exit 1, a message on stderr) unless: the manifest's sha256 is the SHA-256 of the installer
// file, the manifest version, the version argument and the installer file name agree, the url is https on
// download.getvvault.com and ends with the installer's file name, and the recorded size is the file's size.
const crypto = require('crypto')
const fs = require('fs')
const path = require('path')

const HOST = 'download.getvvault.com'

function sha256File(file) {
  const hash = crypto.createHash('sha256')
  const fd = fs.openSync(file, 'r')
  const buffer = Buffer.alloc(1024 * 1024)
  try {
    let read
    while ((read = fs.readSync(fd, buffer, 0, buffer.length, null)) > 0) hash.update(buffer.subarray(0, read))
  } finally {
    fs.closeSync(fd)
  }
  return hash.digest('hex')
}

function fail(message) {
  console.error(`BUILD FAILED: ${message}`)
  process.exit(1)
}

function write(installer, version, manifestPath) {
  if (!fs.existsSync(installer)) fail(`installer not found: ${installer}`)
  const name = path.basename(installer)
  const size = fs.statSync(installer).size
  const manifest = {
    version,
    released: new Date().toISOString().slice(0, 10),
    win_x64: {
      url: `https://${HOST}/${name}`,
      sha256: sha256File(installer),
      size_bytes: size,
      size_mb: Math.round(size / 1048576),
    },
  }
  fs.mkdirSync(path.dirname(manifestPath), { recursive: true })
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n')
  console.log(`Manifest written: ${manifestPath} (sha256 ${manifest.win_x64.sha256}). Nothing was uploaded.`)
}

function check(manifestPath, installer, version) {
  let manifest
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'))
  } catch (err) {
    fail(`cannot read ${manifestPath}: ${err.message}`)
  }
  const asset = manifest && manifest.win_x64
  if (!asset || !asset.url || !asset.sha256) fail('the manifest has no win_x64 url and sha256 (the extension needs both)')
  if (!fs.existsSync(installer)) fail(`installer not found: ${installer}`)
  const name = path.basename(installer)
  const actual = sha256File(installer)
  if (String(asset.sha256).toLowerCase() !== actual) {
    fail(`the manifest sha256 (${asset.sha256}) is not the installer's hash (${actual})`)
  }
  if (manifest.version !== version) fail(`the manifest version (${manifest.version}) differs from the build version (${version})`)
  if (!name.includes(version)) fail(`the installer file name (${name}) does not carry the version ${version}`)
  let url
  try {
    url = new URL(asset.url)
  } catch {
    fail(`the manifest url is not a valid URL: ${asset.url}`)
  }
  if (url.protocol !== 'https:' || url.host.toLowerCase() !== HOST) fail(`the manifest url must be https on ${HOST}: ${asset.url}`)
  if (path.posix.basename(url.pathname) !== name) fail(`the manifest url (${asset.url}) does not end with the installer name ${name}`)
  if (asset.size_bytes !== fs.statSync(installer).size) fail('the manifest size does not match the installer file')
  console.log(`Manifest check passed: version ${version}, sha256 ${actual}`)
}

const [command, a, b, c] = process.argv.slice(2)
if (command === 'write' && a && b) write(a, b, c || path.join(path.dirname(a), 'manifest.json'))
else if (command === 'check' && a && b && c) check(a, b, c)
else fail('usage: node manifest.js write <installer> <version> [manifest] | check <manifest> <installer> <version>')
