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

function log(message) {
  var timeString = (new Date()).toString();
  console.log(timeString + ": " + message);
}

// continuation: function(error, stdout, stderr)
function downloadCerts(host, port, continuation) {
  var minimumHTTPRequest = "GET / HTTP/1.0\\r\\n\\r\\n";
  var command = "echo -n '" + minimumHTTPRequest + "' |" +
                "gnutls-cli --insecure --print-cert " + host +
                " -p " + port + " > /tmp/certs.pem";
  log("downloadCerts: attempting command '" + command + "'");
  exec(command, continuation);
}

function runChecker(host, port, rootPEM, oid, description, continuation) {
  var command = "echo -n '" + rootPEM + "' >> /tmp/certs.pem && " +
                "./ev-checker -c /tmp/certs.pem -o " + oid + " -d '" +
                description + "'";
  log("runChecker: attempting command '" + command + "'");
  exec(command, continuation);
}

function validateHost(hostField) {
  if (!hostField) {
    return null;
  }
  var parsed = url.parse(hostField.indexOf("https://") == 0
                         ? hostField
                         : "https://" + hostField);
  return { host: parsed.hostname,
           port: parsed.port ? parsed.port : "443" };
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
      log("handleRunChecker: " + err);
      response.writeHead(500);
      response.end();
      return;
    }

    var hostport = validateHost(fields['host']);
    var rootPEM = validatePEM(fs.readFileSync(files['rootPEM'].path));
    var oid = validateOID(fields['oid']);
    var description = validateDescription(fields['description']);
    if (!hostport || !rootPEM || !oid || !description) {
      response.writeHead(200);
      var message = "Validation of input parameters failed.";
      if (!hostport) message += "\n(bad test URL)";
      if (!rootPEM) message += "\n(bad root certificate - it should be in PEM format)";
      if (!oid) message += "\n(bad OID)";
      if (!description) message += "\n(description contained invalid input)";
      response.end(message);
      return;
    }
    downloadCerts(hostport.host, hostport.port,
      function(error, stdout, stderr) {
        if (error) {
          response.writeHead(200, { 'Content-Type': 'test/plain' });
          response.end("Downloading certificates from '" + hostport.host +
                       ":" + hostport.port + "' failed. The server may " +
                       "be down or inaccessible from this host.\n" +
                       "Extra debugging output:\n" +
                       stderr);
          return;
        }
        runChecker(hostport.host, hostport.port, rootPEM, oid, description,
          function(error, stdout, stderr) {
            if (error) {
              response.writeHead(200, { 'Content-Type': 'test/plain' });
              response.end("Verifying the certificate at '" + hostport.host +
                           ":" + hostport.port + "' failed. The following " +
                           "additional output may be informative:\n" +
                           stderr);
              return;
            }
            response.writeHead(200, { 'Content-Type': 'test/plain' });
            response.end(stdout);
            return;
          }
        );
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
