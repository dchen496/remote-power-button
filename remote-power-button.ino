#include <limits.h>
#include <ctype.h>

// https://github.com/jcw/ethercard
#include <EtherCard.h>
// https://github.com/rweather/arduinolibs
#include "Crypto/Crypto.h"
#include "Crypto/SHA256.h"
#include "Crypto/RNG.h"

static byte mac[] = { 0x30, 0xd2, 0x7d, 0x04, 0x93, 0x0d };
static byte ip[] = { 18, 102, 218, 11 };
static byte gateway[] = { 18, 102, 218, 1 };

#define HOSTNAME "soba.mit.edu"
#define RNG_EEPROM_ADDR 0

byte Ethernet::buffer[512];
BufferFiller bfill;
char *rxdata;
uint16_t rxdata_len;

void fail() {
  while (1);
}

void setup() {
  Serial.begin(9600);

  // RNG
  RNG.begin(HOSTNAME, RNG_EEPROM_ADDR);

  // Ethernet
  byte firmwareVersion = ether.begin(sizeof Ethernet::buffer, mac, 10);
  Serial.print("Firmware version: ");
  Serial.println(firmwareVersion);
  if (firmwareVersion == 0)
  {
    Serial.println(F("Failed to access Ethernet controller"));
    fail();
  }
  ether.staticSetup(ip, gateway);
  ether.printIp("IP: ", ether.myip);
  ether.printIp("Gateway: ", ether.gwip);
}

static void toHex(uint8_t *in, char *out, size_t nbytes) {
  for (int i = 0; i < nbytes; i++) {
    uint8_t upper = in[i] >> 4;
    out[2*i] = upper < 10 ? upper + '0' : upper - 10 + 'a';
    uint8_t lower = in[i] & 0xf;
    out[2*i+1] = lower < 10 ? lower + '0' : lower - 10 + 'a';
  }
  out[2*nbytes] = '\0';
}

static void fromHex(char *in, uint8_t *out, size_t nbytes) {
  for (int i = 0; i < nbytes; i++) {
    uint8_t upper = isalpha(in[2*i]) ? in[2*i] - 'a' + 10 : in[2*i] - '0';
    uint8_t lower = isalpha(in[2*i+1]) ? in[2*i+1] - 'a' + 10 : in[2*i+1] - '0';
    out[i] = upper << 4 | lower;
  }
}

uint8_t challenge[16];
char challengeHex[33];
uint8_t challengeTest[16];
long challengeIssued;
bool challengeValid = false;
const long challengeExpiry = 3000000; // 30 seconds

const char passwordHash[16] = "password1234";

static void generateChallenge() {
  long now = millis();
  if (challengeValid && now - challengeIssued < challengeExpiry) {
    Serial.println(F("Reusing challenge."));
  } else {
    Serial.print(F("Generating challenge: "));
    challengeIssued = now;
    challengeValid = true;

    while (!RNG.available(sizeof(challenge)))
      RNG.loop();
    RNG.rand(challenge, sizeof(challenge));
    toHex(challenge, challengeHex, sizeof(challenge));

    Serial.println(challengeHex);
  }
}

const char *getPrefix = "GET /";
const char *postPrefix = "POST /";

static word handleGet() {
  Serial.println(F("GET Request."));

  generateChallenge();

  bfill = ether.tcpOffset();
  bfill.emit_p(PSTR(
    "HTTP/1.1 302 Found\r\n"
    "Cache-Control: no-cache\r\n"
    "Location: http://dpchen.me/reboot/form?challenge=$S\r\n"
    "\r\n"
  ), challengeHex);
  Serial.println(F("Request completed."));
  return bfill.position();
}

SHA256 sha256;
uint8_t expectedHash[16];
uint8_t actualHash[16];

static void badRequest() {
  bfill.emit_p(PSTR(
    "HTTP/1.1 400 Bad Request\r\n"
    "Cache-Control: no-cache\r\n"
    "\r\n"
  ));
  Serial.println(F("Bad request."));
}

static void forbidden() {
  bfill.emit_p(PSTR(
    "HTTP/1.1 403 Forbidden\r\n"
    "Cache-Control: no-cache\r\n"
    "\r\n"
  ));
  Serial.println(F("Forbidden request."));
}

static void reboot() {
  // press power button for 5 seconds
  Serial.println(F("Pressing power button."));
  delay(5000);
  Serial.println(F("Unpressing power button."));
}

static word handlePost() {
  Serial.println(F("Request received."));

  // compute expected hash
  sha256.reset();
  sha256.update(passwordHash, sizeof(passwordHash));
  sha256.update(challenge, sizeof(challenge));
  sha256.finalize(expectedHash, sizeof(expectedHash));

  // check against actual hash
  char *remaining = rxdata + strlen(postPrefix);
  uint16_t remaining_len = rxdata_len - strlen(postPrefix);
  if (remaining_len < sizeof(expectedHash)*2) {
    badRequest();
    return bfill.position();
  }

  fromHex(remaining, actualHash, sizeof(actualHash));
  for (int i = 0; i < sizeof(expectedHash); i++) {
    if (actualHash[i] != expectedHash[i]) {
      forbidden();
      return bfill.position();
    }
  }

  // check expiry
  long now = millis();
  if (!challengeValid || now - challengeIssued >= challengeExpiry) {
    Serial.println(F("Challenge invalid/expired."));
    forbidden();
    return bfill.position();
  }
  // invalidate challenge
  challengeValid = false;

  reboot();

  bfill.emit_p(PSTR(
    "HTTP/1.1 200 OK\r\n"
    "Cache-Control: no-cache\r\n"
    "\r\n"
    "<html><body>Rebooted.</body></html>\r\n"
    "\r\n"
  ));

  Serial.println(F("Request completed."));
  return bfill.position();
}

void loop() {
  RNG.loop();

  word len = ether.packetReceive();
  word pos = ether.packetLoop(len);

  // check if valid tcp data is received
  if (pos) {
    long now = millis();
    // protect against overflow by invalidating whenever now is before the
    // challenge was issued
    if (now - challengeIssued >= challengeExpiry || now < challengeIssued) {
      challengeValid = false;
    }

    // help the RNG a bit, but don't give it entropy credit
    RNG.stir((uint8_t *) &now, sizeof(now), 0);

    rxdata = (char *) Ethernet::buffer + pos;
    rxdata_len = len - pos;
    bfill = ether.tcpOffset();
    word txpos;
    if (rxdata_len >= strlen(getPrefix) && strncmp(getPrefix, rxdata, strlen(getPrefix)) == 0) {
      txpos = handleGet();
    } else if (rxdata_len >= strlen(postPrefix) && strncmp(postPrefix, rxdata, strlen(postPrefix)) == 0) {
      txpos = handlePost();
    }
    ether.httpServerReply(txpos); // send web page data
    pos = 0;
  }
}

