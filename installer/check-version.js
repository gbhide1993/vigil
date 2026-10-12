// One version everywhere: the installer script, the tray (package.json) and the backend
// (VERSION in backend/main.py, reported by /api/health) must agree. build.bat runs this first.
//   node check-version.js           exit 1 with a message if they differ
//   node check-version.js --print   print the agreed version (exit 1 if they differ)
const fs = require('fs')
const path = require('path')

const root = process.argv[2] && !process.argv[2].startsWith('--') ? process.argv[2] : path.resolve(__dirname, '..')

function read(rel) {
  return fs.readFileSync(path.join(root, rel), 'utf8')
}

function find(rel, regex, label) {
  const m = read(rel).match(regex)
  if (!m) {
    console.error(`BUILD FAILED: could not find the ${label} in ${rel}`)
    process.exit(1)
  }
  return m[1]
}

const versions = {
  'installer/vigil-setup.iss (AppVersion)': find('installer/vigil-setup.iss', /^#define AppVersion "([^"]+)"/m, 'AppVersion define'),
  'tray/package.json (version)': JSON.parse(read('tray/package.json')).version,
  'backend/main.py (VERSION, shown by /api/health)': find('backend/main.py', /^VERSION = "([^"]+)"/m, 'VERSION constant'),
}

const distinct = new Set(Object.values(versions))
if (distinct.size !== 1) {
  console.error('BUILD FAILED: the version differs between the installer, the tray and the backend:')
  for (const [where, version] of Object.entries(versions)) console.error(`  ${version.padEnd(12)} ${where}`)
  console.error('Set all three to the same number and build again.')
  process.exit(1)
}

const [version] = distinct
if (process.argv.includes('--print')) console.log(version)
else console.log(`Version check passed: ${version}`)
