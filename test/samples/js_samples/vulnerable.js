// Test file: JavaScript security patterns

// SSRF via fetch
function fetchUrl(userUrl) {
  fetch(userUrl).then(r => r.json());
}

// Command injection via exec
const { exec } = require('child_process');
function runCommand(input) {
  exec('ls ' + input);
}

// XSS via innerHTML
function renderUser(name) {
  document.getElementById('output').innerHTML = name;
}

// Eval injection
function evaluate(expr) {
  eval(expr);
}

// Path traversal
const fs = require('fs');
function readFile(userPath) {
  fs.readFile(userPath, 'utf8');
}
