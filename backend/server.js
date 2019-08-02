const fs = require('fs');
const Hapi = require('hapi');
const path = require('path');
const Boom = require('boom');
const ext = require('commander');
const jsonwebtoken = require('jsonwebtoken');
const request = require('request');

// The developer rig uses self-signed certificates.  Node doesn't accept them
// by default.  Do not use this in production.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// Use verbose logging during development.  Set this to false for production.
const verboseLogging = true;
const verboseLog = verboseLogging ? console.log.bind(console) : () => { };

// Service state variables
const serverTokenDurationSec = 30;          // our tokens for pubsub expire after 30 seconds
const userCooldownMs = 1000;                // maximum input rate per user to prevent bot abuse
const userCooldownClearIntervalMs = 60000;  // interval to reset our tracking object
const channelCooldownMs = 1000;             // maximum broadcast rate per channel
const bearerPrefix = 'Bearer ';             // HTTP authorization headers have this prefix
const cooldownData = {};
const channelCooldowns = {};                // rate limit compliance
let userCooldowns = {};                     // spam prevention
let ingame = true;

const STRINGS = {
  secretEnv: usingValue('secret'),
  clientIdEnv: usingValue('client-id'),
  ownerIdEnv: usingValue('owner-id'),
  serverStarted: 'Server running at %s',
  secretMissing: missingValue('secret', 'EXT_SECRET'),
  clientIdMissing: missingValue('client ID', 'EXT_CLIENT_ID'),
  ownerIdMissing: missingValue('owner ID', 'EXT_OWNER_ID'),
  messageSendError: 'Error sending message to channel %s: %s',
  pubsubResponse: 'Message to c:%s returned %s',
  executingCommand: 'Executing command for c:%s on behalf of u:%s',
  broadcast: 'Broadcasting %s for c:%s',
  send: 'Sending information %s to c:%s',
  cooldown: 'Please wait before clicking again',
  invalidAuthHeader: 'Invalid authorization header',
  invalidJwt: 'Invalid JWT',
};

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
    // If you need a certificate, execute "npm run cert".
    cert: fs.readFileSync(serverPathRoot + '.crt'),
    key: fs.readFileSync(serverPathRoot + '.key'),
  };
}
const server = new Hapi.Server(serverOptions);

(async () => {

  server.route({
    method: 'POST',
    path: '/execute',
    handler: commandHandler,
  });

  server.route({
    method: 'POST',
    path: '/setGameInfo',
    handler: setGameInfo,
  });

  server.route({
    method: 'GET',
    path: '/cooldowns',
    handler: QueryHandler,
  });

  server.route({
    method: 'GET',
    path: '/commandStack',
    handler: retrieveStack,
  });

  // Start the server.
  await server.start();
  console.log(STRINGS.serverStarted, server.info.uri);

  // Periodically clear cool-down tracking to prevent unbounded growth due to
  // per-session logged-out user tokens.
  setInterval(() => { userCooldowns = {}; }, userCooldownClearIntervalMs);
})();

function usingValue(name) {
  return `Using environment variable for ${name}`;
}

function missingValue(name, variable) {
  const option = name.charAt(0);
  return `Extension ${name} required.\nUse argument "-${option} <${name}>" or environment variable "${variable}".`;
}

// Get options from the command line or the environment.
function getOption(optionName, environmentName) {
  const option = (() => {
    if (ext[optionName]) {
      return ext[optionName];
    } else if (process.env[environmentName]) {
      console.log(STRINGS[optionName + 'Env']);
      return process.env[environmentName];
    }
    console.log(STRINGS[optionName + 'Missing']);
    process.exit(1);
  })();
  console.log(`Using "${option}" for ${optionName}`);
  return option;
}

// Verify the header and the enclosed JWT.
function verifyAndDecode(header) {
  if (header.startsWith(bearerPrefix)) {
    try {
      const token = header.substring(bearerPrefix.length);
      return jsonwebtoken.verify(token, secret, { algorithms: ['HS256'] });
    }
    catch (ex) {
      throw Boom.unauthorized(STRINGS.invalidJwt);
    }
  }
  throw Boom.unauthorized(STRINGS.invalidAuthHeader);
}

function commandHandler(req) {
  if (ingame == "1"){
      // Verify all requests.
      const payload = verifyAndDecode(req.headers.authorization);
      const { channel_id: channelId, opaque_user_id: opaqueUserId, user_id: userId } = payload;

      let data = req.payload;
      let commandData = {command: data.command, time: Date.now() / 1000 + 20, user: data.user};
      // Bot abuse prevention:  don't allow a user to spam the button.
      if (userIsInCooldown(opaqueUserId)) {
        throw Boom.tooManyRequests(STRINGS.cooldown);
      }
      verboseLog(STRINGS.executingCommand, channelId, opaqueUserId);


      if (!cooldownData)
      cooldownData = {};
      
      cooldownData[data.command] = commandData;


      attemptBroadcast(channelId, data.command);

      return cooldownData;
    }
    return false;
}
function setGameInfo(req) {
  ingame = req.payload.ingame;
  verboseLog(req.payload);
  const commandData = cooldownData || {};
  return commandData;
}
function QueryHandler(req) {
  // Verify all requests.
  const payload = verifyAndDecode(req.headers.authorization);

  const { channel_id: channelId, opaque_user_id: opaqueUserId } = payload;
  const commandData = cooldownData || {};
  verboseLog(STRINGS.send, commandData, opaqueUserId);
  return commandData;
}
function retrieveStack(req) {
  const { channel_id: channelId, opaque_user_id: opaqueUserId } = req;
  const commandData = cooldownData || {};
  verboseLog(STRINGS.send, commandData, opaqueUserId);
  return commandData;
}

function attemptBroadcast(channelId, commandName) {
  // Check the cool-down to determine if it's okay to send now.
  const now = Date.now() / 1000;

    sendBroadcast(channelId, commandName);

}

function sendBroadcast(channelId, commandName) {
  // Set the HTTP headers required by the Twitch API.
  const headers = {
    'Client-ID': clientId,
    'Content-Type': 'application/json',
    'Authorization': bearerPrefix + makeServerToken(channelId),
  };

  // Create the POST body for the Twitch API request.
  const commandData = JSON.stringify(cooldownData[commandName]) || "{time: 0, command: commandName, user: twitch}";
  const body = JSON.stringify({
    content_type: 'application/json',
    message: commandData,
    targets: ['broadcast'],
  });

  // Send the broadcast request to the Twitch API.
  verboseLog(STRINGS.broadcast, commandData, channelId);
  request(
    `https://api.twitch.tv/extensions/message/${channelId}`,
    {
      method: 'POST',
      headers,
      body,
    }
    , (err, res) => {
      if (err) {
        console.log(STRINGS.messageSendError, channelId, err);
      } else {
        verboseLog(STRINGS.pubsubResponse, channelId, res.statusCode);
      }
    });
}

function getUserInfo(data) {
  verboseLog("name: ", data.display_name);
}

// Create and return a JWT for use by this service.
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
