const fs = require('fs');
const Hapi = require('hapi');
const path = require('path');
const Boom = require('boom');
const ext = require('commander');
const jsonwebtoken = require('jsonwebtoken');
const request = require('request');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const serverTokenDurationSec = 30;          // our tokens for pubsub expire after 30 seconds
const userCooldownMs = 30;                // maximum input rate per user to prevent bot abuse
const userCooldownClearIntervalMs = 60000;  // interval to reset our tracking object
const bearerPrefix = 'Bearer ';             // HTTP authorization headers have this prefix
const clientID = 'js597m7tbf5l0g5vzcqgi3v8t7t5y2';
const userHeader = { 'Client-ID': clientID };
let userCooldowns = {};    
let commandData = {};
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
  host: process.env.IP   || process.env.OPENSHIFT_NODEJS_IP || '0.0.0.0',
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
  createRoute('POST', '/coordinator', coordinatorHandler);
  createRoute('GET', '/retrieve', clientHandler);

  await server.start();
  console.log("Server running at %s", server.info.uri);

  setInterval(() => { 
    let now = Date.now() / 1000;
    Object.keys(userCooldowns).forEach(function (item) {
      if(userCooldowns[item] < now)
        delete userCooldowns[item];
    });
   }, userCooldownClearIntervalMs);

})();

function createRoute(method, path, handler) {
  server.route({
    method: method,
    path: path,
    handler: handler,
  });
}

function loadCommandData() {
  let raw = fs.readFileSync(path.resolve(__dirname, '..')+'/config.json');
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
  const now = Date.now() / 1000;
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
  let client = payloadData.name;

  if(gameData.type == 0 || (gameData.type == 1 && commandData[command].loud))
    throw Boom.methodNotAllowed("Game state dissallows command");
  // Dont execute if command is on cooldown
  if(isCommandOnCooldown(command, client, time))
    throw Boom.notAcceptable("Command is still on cooldown");
  if (userIsInCooldown(opaqueUserId)) {
      throw Boom.tooManyRequests("Too many requests, please wait");
    }
  console.log(`Executing ${command}`);

  commandData[command].time = time;
  commandData[command].client = client;

  let message = {command: command, time: time, client: client};

  sendBroadcast(channelId, message);
  return userCooldowns[opaqueUserId]
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
  const { user_id: userID, opaque_user_id: opaqueUserId } = payload;
  console.log(`Sending data to ${userID}`);
  let username = getUserName(userID);
  return new Promise((resolve, reject) => {
    username.then((value) => {
      let reply = {commandData: commandData, gameData: gameData, cd: userCooldowns[opaqueUserId], name: value, money: 100};
      resolve(reply);
    });
  })
}
function getUserName(uid){
  return new Promise((resolve, reject) => {
    request({url:`https://api.twitch.tv/helix/users?id=${uid}`, method: 'GET', headers: userHeader}, function(err, res, body) {
      if(err)
        reject();

      let parsed = JSON.parse(body);
      let [user] = parsed.data;
      resolve(user.display_name)
      
    });
  });
}

function makeListenToken(channelId) {
  const payload = {
    exp: Math.floor(Date.now() / 1000) + serverTokenDurationSec,
    channel_id: channelId,
    user_id: ownerId,
    role: 'external',
    pubsub_perms: {
      listen: ['*']
    },
  };
  return jsonwebtoken.sign(payload, secret, { algorithm: 'HS256' });
}
function coordinatorHandler(req) {
  if (!req.headers.authorization || req.headers.authorization != clientID)
    throw Boom.unauthorized("Invalid authorization header");
  let message = req.payload;
  if (message.game) {
    gameData = message.game;
    let msg = {gameData: gameData};
    sendBroadcast(message.channel, msg);
  }

  let reply = {};
  if(message.needToken)
    reply = {token: makeListenToken(message.channel)};

  return JSON.stringify(reply)
}