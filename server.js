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

function runChecker(host, port, rootPEM, oid, description, continuation) {
  var minimumHTTPRequest = "GET / HTTP/1.0\r\n\r\n";
  var command = "echo -n '" + minimumHTTPRequest + "' |" +
                "gnutls-cli --print-cert " + host + " -p " + port +
                " 2> /dev/null > /tmp/certs.pem && " +
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

function validateHost(hostField) {
  if (!hostField) {
    return null;
  }
  var parsed = url.parse(hostField.indexOf("https://") == 0
                         ? hostField
                         : "https://" + hostField);
  return { host: parsed.hostname,
           port: parsed.port };
}

function validatePEM(rootPEMContents) {
  if (!rootPEMContents) {
    return null;
  }
  var pemRegEx = /^-----BEGIN CERTIFICATE-----[0-9A-Za-z+\/=]+-----END CERTIFICATE-----$/;
  var rootPEMNoNewlines = rootPEMContents.toString().replace(/[\r\n]/g, "");
  return pemRegEx.test(rootPEMNoNewlines) ? rootPEMContents : null;
}

function validateOID(oidField) {
  var oidRegEx = /^([0-9]+\.)*[0-9]+$/;
  return oidRegEx.test(oidField) ? oidField : null;
}

function validateDescription(descriptionField) {
  var descriptionRegEx = /^[0-9A-Za-z ]+$/;
  return descriptionRegEx.test(descriptionField) ? descriptionField : null;
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

    var hostandport = validateHost(fields['host']);
    var rootPEM = validatePEM(fs.readFileSync(files['rootPEM'].path));
    var oid = validateOID(fields['oid']);
    var description = validateDescription(fields['description']);
    if (!hostandport || !rootPEM || !oid || !description) {
      response.writeHead(200);
      response.end("Validation of input parameters failed.");
      return;
    }
    runChecker(hostandport.host, hostandport.port, rootPEM, oid, description,
      function(result) {
        response.writeHead(200, {
          'Content-Type': 'test/plain'
        });
        response.end(result);
      }
    );
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
