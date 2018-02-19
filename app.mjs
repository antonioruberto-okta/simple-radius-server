import { createSocket } from 'dgram';
import radius from 'radius';
import speakeasy from 'speakeasy';
import yargs from 'yargs';

const { argv } = yargs.usage('Simple RADIUS Server\nUsage: $0')
  .example('$0 --u user@example --w 123456 --t')
  .alias('p', 'port')
  .describe('port', 'RADIUS server port')
  .default('port', 1812)
  .number('port')
  .alias('s', 'secret')
  .describe('secret', 'RADIUS shared secret')
  .string('secret')
  .demandOption('secret')
  .alias('u', 'username')
  .describe('username', 'RADIUS User-Name for Access-Request')
  .string('username')
  .array('username')
  .demandOption('username')
  .alias('w', 'password')
  .describe('password', 'Static password (totp=false) or base32-encoded TOTP shared secret (totp=true) for Access-Request')
  .string('password')
  .array('password')
  .demandOption('password')
  .alias('t', 'totp')
  .describe('totp', 'Determines whether to compute TOTP (true) or use static value (false) to validate Access-Request')
  .boolean('totp')
  .check(((input) => input.username.length === input.password.length));

const userPasswords = {};

for (let i = 0; i < argv.username.length; i += 1) {
  userPasswords[argv.username[i].toLowerCase()] = argv.password[i];
}

console.log(`RADIUS server port: ${argv.port}`);
console.log(`RADIUS shared secret: ${argv.secret}`);
console.log();

const server = createSocket('udp4');

server.on('message', (msg, rinfo) => {
  const packet = radius.decode({ packet: msg, secret: argv.secret });

  if (packet.code !== 'Access-Request') {
    console.log(`Unknown RADIUS packet type ${packet.code}`);
    return;
  }

  const username = packet.attributes['User-Name'];
  const token = packet.attributes['User-Password'];

  console.log(`Access-Request for ${username}`);

  const userPassword = userPasswords[username.toLowerCase()];

  let code;
  let reason = '';
  if (!userPassword) {
    code = 'Access-Reject';
    reason = 'User-Name is invalid';
  } else if (argv.totp) {
    const totpValid = speakeasy.totp.verify({ secret: userPassword, encoding: 'base32', token });

    if (totpValid) {
      code = 'Access-Accept';
    } else {
      code = 'Access-Reject';
      reason = 'User-Password is not a valid totp';
    }
  } else {
    const passwordValid = token === userPassword;

    if (passwordValid) {
      code = 'Access-Accept';
    } else {
      code = 'Access-Reject';
      reason = 'User-Password is not the correct password';
    }
  }

  const response = radius.encode_response({ packet, code, secret: argv.secret });

  console.log(`Sending ${code}`);
  if (reason) {
    console.log(reason);
  }

  server.send(response, 0, response.length, rinfo.port, rinfo.address, (err) => {
    if (err) {
      console.log(`Error sending response to ${rinfo.address}:${rinfo.port}`);
    }
  });
});

server.on('listening', () => {
  const address = server.address();

  console.log(`RADIUS server listening on ${address.address}:${address.port}`);
});

server.bind(argv.port);
