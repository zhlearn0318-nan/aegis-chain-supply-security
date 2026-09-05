'use strict';

const fs = require('fs');
const path = require('path');
const eventFile = process.env.AEGIS_EVENT_FILE || '';
const round = process.env.AEGIS_TEST_ROUND || 'unknown';

function clean(value, limit = 300) {
  return String(value ?? '').replace(/[\x00-\x1f\x7f]/g, ' ').replace(/\s+/g, ' ').slice(0, limit);
}
function emit(payload) {
  if (!eventFile) return;
  payload.round = round;
  try { fs.appendFileSync(eventFile, JSON.stringify(payload) + '\n', {encoding: 'utf8'}); } catch (_) {}
}
emit({type: 'telemetry.ready', collector: 'node_preload_v1'});

const child = require('child_process');
for (const name of ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync']) {
  const original = child[name];
  if (typeof original !== 'function') continue;
  child[name] = function(...args) {
    emit({type: 'process.spawn', executable: path.basename(clean(args[0]))});
    return original.apply(this, args);
  };
}

const net = require('net');
const originalConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function(...args) {
  const options = typeof args[0] === 'object' ? args[0] : {};
  emit({type: 'socket.connect', host: clean(options.host || args[0]), port: options.port || args[1]});
  return originalConnect.apply(this, args);
};

for (const name of ['readFileSync', 'writeFileSync', 'appendFileSync', 'unlinkSync', 'rmSync']) {
  const original = fs[name];
  if (typeof original !== 'function') continue;
  fs[name] = function(...args) {
    const target = clean(args[0]);
    if (target !== eventFile) {
      emit({type: 'file.open', path: target, operation: name});
      if (target.toLowerCase().startsWith('/workspace/decoys/')) {
        emit({type: 'decoy.read', marker_id: path.parse(target).name});
      }
    }
    return original.apply(this, args);
  };
}
