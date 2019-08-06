const fs = require('fs');
const Hapi = require('hapi');
const path = require('path');
const Boom = require('boom');
const ext = require('commander');
const jsonwebtoken = require('jsonwebtoken');
const request = require('request');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const serverTokenDurationSec = 30;          // our tokens for pubsub expire after 30 seconds
const userCooldownMs = 1000;                // maximum input rate per user to prevent bot abuse
const userCooldownClearIntervalMs = 60000;  // interval to reset our tracking object
const channelCooldownMs = 1000;             // maximum broadcast rate per channel
const bearerPrefix = 'Bearer ';             // HTTP authorization headers have this prefix
const userHeader = { 'Client-ID': 'js597m7tbf5l0g5vzcqgi3v8t7t5y2' };
let userCooldowns = {};    
let commandData = {};
let commandStack = [];
let gameData = {type: 0};

ext.
  version(require('../package.json').version).
  option('-s, --secret <secret>', 'Extension secret').
  option('-c, --client-id <client_id>', 'Extension client ID').
  option('-o, --owner-id <owner_id>', 'Extension owner ID').
  parse(process.argv);

const ownerId = getOption('ownerId', 'EXT_OWNER_ID');
const secret = Buffer.from(getOption('secret', 'EXT_SECRET'), 'base64');
const clientId = getOption('clientId', 'EXT_CLIENT_ID');

const serverOptions = {
  host: process.env.IP   || process.env.OPENSHIFT_NODEJS_IP || 'localhost',
  port: process.env.PORT || process.env.OPENSHIFT_NODEJS_PORT || 8080,
  routes: {
    cors: {
      origin: ['*'],
    },
  },
};

const serverPathRoot = path.resolve(__dirname, '..', 'conf', 'server');
if (fs.existsSync(serverPathRoot + '.crt') && fs.existsSync(serverPathRoot + '.key')) {
  serverOptions.tls = {
    cert: fs.readFileSync(serverPathRoot + '.crt'),
    key: fs.readFileSync(serverPathRoot + '.key'),
  };
}
const server = new Hapi.Server(serverOptions);

(async () => {
  
  loadCommandData();
  createRoute('POST', '/execute', executeHandler);
  createRoute('GET', '/retrieve', clientHandler);

  await server.start();
  console.log("Server running at %s", server.info.uri);

  setInterval(() => { userCooldowns = {}; }, userCooldownClearIntervalMs);

})();

function createRoute(method, path, handler) {
  server.route({
    method: method,
    path: path,
    handler: handler,
  });
}

function loadCommandData() {
  let raw = fs.readFileSync('../config.json');
  commandData = JSON.parse(raw);
}

function getOption(optionName, environmentName) {
  const option = (() => {
    if (ext[optionName]) {
      return ext[optionName];
    } else if (process.env[environmentName]) {
      return process.env[environmentName];
    }
    process.exit(1);
  })();
  console.log(`Using "${option}" for ${optionName}`);
  return option;
}

function verifyAndDecode(header) {
  if (header.startsWith(bearerPrefix)) {
    try {
      const token = header.substring(bearerPrefix.length);
      return jsonwebtoken.verify(token, secret, { algorithms: ['HS256'] });
    }
    catch (ex) {
      throw Boom.unauthorized("Invalid JWT");
    }
  }
  throw Boom.unauthorized("Invalid authorization header");
}

function makeServerToken(channelId) {
  const payload = {
    exp: Math.floor(Date.now() / 1000) + serverTokenDurationSec,
    channel_id: channelId,
    user_id: ownerId, // extension owner ID for the call to Twitch PubSub
    role: 'external',
    pubsub_perms: {
      send: ['*'],
    },
  };
  return jsonwebtoken.sign(payload, secret, { algorithm: 'HS256' });
}

function userIsInCooldown(opaqueUserId) {
  // Check if the user is in cool-down.
  const cooldown = userCooldowns[opaqueUserId];
  const now = Date.now();
  if (cooldown && cooldown > now) {
    return true;
  }
  // Voting extensions must also track per-user votes to prevent skew.
  userCooldowns[opaqueUserId] = now + userCooldownMs;
  return false;
}

function isCommandOnCooldown(command, client, time){
  let data = commandData[command]
  
  if (data.time && data.client == client && data.time + data.user > time)
    return true;
  else if(data.time && data.client != client && data.time + data.global > time)
    return true;

  return false;
}

function executeHandler(req) {
  const payload = verifyAndDecode(req.headers.authorization);
  const { channel_id: channelId, opaque_user_id: opaqueUserId } = payload;

  let payloadData = req.payload;
  let command = payloadData.command
  let time = Date.now() / 1000;
  let client = payloadData.uid;

  // Bot abuse prevention:  don't allow a user to spam the button.
  if (userIsInCooldown(opaqueUserId)) {
    throw Boom.tooManyRequests("Too many requests, please wait");
  }
  // Dont execute if command is on cooldown
  if(isCommandOnCooldown(command, client, time))
    throw Boom.notAcceptable("Command is still on cooldown");

  console.log(`Executing ${command}`);

  commandData[command].time = time;
  commandData[command].client = client;

  let message = {command: command, time: time, client: client};

  sendBroadcast(channelId, message);
  //commandStack.push(message);
  return message;
}

function sendBroadcast(channelId, message) {
  // Set the HTTP headers required by the Twitch API.
  const headers = {
    'Client-ID': clientId,
    'Content-Type': 'application/json',
    'Authorization': bearerPrefix + makeServerToken(channelId),
  };

  // Create the POST body for the Twitch API request.
  const data = JSON.stringify(message)
  const body = JSON.stringify({
    content_type: 'application/json',
    message: data,
    targets: ['broadcast'],
  });

  // Send the broadcast request to the Twitch API.
  console.log(`Broadcasting ${data}`);
  request(`https://api.twitch.tv/extensions/message/${channelId}`,
    {method: 'POST',
      headers,
      body,
    }
    , (err, res) => {
      if (err) {
        console.log("Error sending message");
      } else {
        console.log(`Message returned ${res.statusCode}`);
      }
  });
}

function clientHandler(req) {
  const payload = verifyAndDecode(req.headers.authorization);
  const { user_id: userID } = payload;
  console.log(`Sending data to ${userID}`);
  let reply = {commandData: commandData, gameData: gameData};
  return reply;
}

function getUserName(uid){
  var username = "";
  request({url:`https://api.twitch.tv/helix/users?id=${uid}`, method: 'GET', headers: userHeader}, function(err, res, body) {
    if(!err){
      let parsed = JSON.parse(body);
      let [user] = parsed.data;
      username = user.display_name
    }
  });
  return username;
}