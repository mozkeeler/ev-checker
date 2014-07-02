/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

var http = require('http');
var fs = require('fs');
var formidable = require('formidable');
var exec = require('child_process').exec;
var url = require('url');

function handleFile(response, filename) {
  response.writeHead(200);
  response.end(fs.readFileSync(filename ? filename : "index.html"));
}

function runChecker(host, rootPEM, oid, description, continuation) {
  var command = "gnutls-cli --print-cert " + host + " < /dev/null " +
                "2> /dev/null > /tmp/certs.pem && " +
                "echo -n '" + rootPEM + "' >> /tmp/certs.pem && " +
                "./ev-checker -c /tmp/certs.pem -o " + oid + " -d '" +
                description + "'";
  exec(command, function(error, stdout, stderr) {
    if (error) {
      console.log("runChecker: " + error);
      continuation(error.toString());
    } else {
      continuation(stdout);
    }
  });
}

function handleRunChecker(request, response) {
  var form = new formidable.IncomingForm();
  form.parse(request, function(err, fields, files) {
    if (err) {
      console.log("handleRunChecker: " + err);
      response.writeHead(500);
      response.end();
      return;
    }

    var urlFromHost = url.parse("https://" + fields['host']);
    var rootPEM = fs.readFileSync(files['rootPEM'].path);
    var oid = fields['oid'];
    var description = fields['description'];
    runChecker(urlFromHost.host, rootPEM, oid, description, function(result) {
      response.writeHead(200, {
        'Content-Type': 'test/plain'
      });
      response.end(result);
    });
  });
}

function handleRequest(request, response) {
  switch (request.url) {
    case "/":
    case "/index.html":
    case "/index.css":
      handleFile(response, request.url.slice(1));
      break;
    case "/run-checker":
      handleRunChecker(request, response);
      break;
    default:
      response.writeHead(404);
      response.end();
      break;
  }
}

var server = http.createServer(handleRequest);
server.listen(8000);
