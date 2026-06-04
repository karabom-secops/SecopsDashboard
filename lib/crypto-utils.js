'use strict';

const crypto = require('crypto');

const ALGO = 'aes-256-gcm';

function getKey() {
  const hex = process.env.INTEGRATION_ENCRYPT_KEY;
  if (!hex || hex.length !== 64) {
    throw new Error('INTEGRATION_ENCRYPT_KEY must be a 64-character hex string (32 bytes). Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  }
  return Buffer.from(hex, 'hex');
}

function encrypt(plaintext) {
  const key    = getKey();
  const iv     = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  const enc    = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag    = cipher.getAuthTag();
  return {
    enc: Buffer.concat([enc, tag]).toString('hex'),
    iv:  iv.toString('hex'),
  };
}

function decrypt(encHex, ivHex) {
  const key      = getKey();
  const buf      = Buffer.from(encHex, 'hex');
  const iv       = Buffer.from(ivHex, 'hex');
  const tag      = buf.slice(-16);
  const data     = buf.slice(0, -16);
  const decipher = crypto.createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);
  return decipher.update(data).toString('utf8') + decipher.final('utf8');
}

module.exports = { encrypt, decrypt };
