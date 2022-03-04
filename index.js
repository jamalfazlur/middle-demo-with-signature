
const crypto = require('crypto');
const express = require('express');
const http = require('http');
const path = require("path");
const bodyParser = require('body-parser');
const axios = require('axios');

var app = express();

var server = http.createServer(app);

app.use(bodyParser.urlencoded({extended: false}));
app.use(express.static(path.join(__dirname,'./public')));

app.get('/re-middle-tester', function(req,res){
  res.sendFile(path.join(__dirname,'./public/index.html'));
});

server.listen(3000, function(){
  console.log("server is running on: http://localhost:3000/re-middle-tester");
});

const STRING_PEMBATAS = "------------------------------------------------------------------------------------------------------------------";


app.post('/', function(req,res){
  let myJson = new Object();
  let riskEnvironment = req.body.RE_ENV;

  for(propertyName in req.body) {
    if(propertyName != 'RE_ENV' && req.body[propertyName] != ""){
      myJson[propertyName] = req.body[propertyName];
    }
  }

  let { PARTNER_ID, SECRET_KEY, TRANSACTION_ID } = myJson;

  let requestTimestamp = new Date(Date.now());

  // Generate Digest from JSON Body, For HTTP Method GET/DELETE don't need generate Digest
  console.log("----- Digest -----");
  let digest = generateDigest(JSON.stringify(myJson));
  console.log(digest);
  console.log();

  // Generate Header Signature
  let headerSignature = generateSignature(
    PARTNER_ID,
    TRANSACTION_ID,
    requestTimestamp.toISOString(),
    "/RiskMiddle/screening", 
    digest,
    SECRET_KEY);

  console.log("----- Header Signature -----")
  console.log(headerSignature)

  // ---------------------------------- HIT RE-MIDDLE ----------------------------------
  let reMiddleResponse = '';
  let config = {
    method: 'post',
    url: riskEnvironment,
    headers: {
      'Content-Type': 'application/json',
      'Client-Id': PARTNER_ID,
      'Request-Id': TRANSACTION_ID,
      'Request-Timestamp': requestTimestamp.toISOString(),
      'Request-Target': '/RiskMiddle/screening',
      'Digest': digest,
      'Signature': headerSignature
    },
    data : JSON.stringify(myJson)
  }

  axios(config)
  .then(function (response) {
    reMiddleResponse = JSON.stringify(response.data);
    console.log(JSON.stringify(response.data));

    res.send(`${STRING_PEMBATAS}<br/>
            RiskEngine URL: ${riskEnvironment}<br/>
            ${STRING_PEMBATAS}<br/>
            ----------------------------------------------< HEADER >---------------------------------------------------<br/>
            ${STRING_PEMBATAS}<br/>
            Client-Id: ${PARTNER_ID}<br/>
            Request-Id: ${TRANSACTION_ID}<br/>
            Digest: ${digest} <br/>
            RequestTimestamp: ${requestTimestamp.toISOString()}<br/>
            HeaderSignature: ${headerSignature} <br/>
            ${STRING_PEMBATAS}<br/>
            ----------------------------------------------< BODY >-------------------------------------------------------<br/>
            ${STRING_PEMBATAS}<br/>
            <pre>${JSON.stringify(myJson, undefined, 4)}</pre><br/>
            ${STRING_PEMBATAS}<br/>
            RE-Middle Response: ${reMiddleResponse}`);
  })
  .catch(function (error) {
    res.send(`Error: ${error}`)
    console.log(error);
  });
  
});


// ----------------------------- SIGNATURE MODULE -----------------------------

// Generate Digest
function generateDigest(jsonBody) {
  let jsonStringHash256 = crypto.createHash('sha256').update(jsonBody,"utf-8").digest();
  
  let bufferFromJsonStringHash256 = Buffer.from(jsonStringHash256);
  return bufferFromJsonStringHash256.toString('base64'); 
}

function generateSignature(clientId, requestId, requestTimestamp, requestTarget, digest, secret) {
  // Prepare Signature Component
  console.log("----- Component Signature -----")
  let componentSignature = "Client-Id:" + clientId;
  componentSignature += "\n";
  componentSignature += "Request-Id:" + requestId;
  componentSignature += "\n";
  componentSignature += "Request-Timestamp:" + requestTimestamp;
  componentSignature += "\n";
  componentSignature += "Request-Target:" + requestTarget;
  // If body not send when access API with HTTP method GET/DELETE
  if (digest) {
      componentSignature += "\n";
      componentSignature += "Digest:" + digest;
  }

  console.log(componentSignature.toString());
  console.log();

  // Calculate HMAC-SHA256 base64 from all the components above
  let hmac256Value = crypto.createHmac('sha256', secret)
                 .update(componentSignature.toString())
                 .digest();  
    
  let bufferFromHmac256Value = Buffer.from(hmac256Value);
  let signature = bufferFromHmac256Value.toString('base64');
  // Prepend encoded result with algorithm info HMACSHA256=
  return "HMACSHA256="+signature 
}
  

