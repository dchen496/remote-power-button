#include <limits.h>
#include <ctype.h>
#include <avr/pgmspace.h>

// https://github.com/jcw/ethercard
#include <EtherCard.h>
// https://github.com/rweather/arduinolibs
#include "Crypto/Crypto.h"
#include "Crypto/SHA256.h"
#include "Crypto/RNG.h"

// Use reboot.py to generate the password hash and the salt.

#define HOSTNAME "soba.mit.edu"
#define ETHERNET_CS_PIN 10
const static byte mac[] = { 0x30, 0xd2, 0x7d, 0x04, 0x93, 0x0d };
const static byte ip[] = { 18, 102, 218, 11 };
const static byte gateway[] = { 18, 102, 218, 1 };
byte Ethernet::buffer[512];
static BufferFiller bfill;
static char *rxdata;
static uint16_t rxdata_len;

#define RNG_EEPROM_ADDR 0

#define CHALLENGE_EXPIRY 30000 // 30 seconds
#define CHALLENGE_SIZE 32
static uint8_t challenge[CHALLENGE_SIZE];
static char challenge_hex[2*CHALLENGE_SIZE + 1];
static long challenge_issued;
static bool challenge_valid = false;

static uint8_t expected_hash[CHALLENGE_SIZE];
static uint8_t actual_hash[CHALLENGE_SIZE];

#define SWITCH_PIN 19 // pin A5
static uint8_t press_length;

static const char get_challenge_route[] PROGMEM = "GET /challenge";
static const char post_reboot_route[] PROGMEM = "POST /reboot/"; // POST /reboot/[SHA256(password_hash || challenge)]

static SHA256 sha256;

static void fail() {
  while (1);
}

void setup() {
  Serial.begin(115200);

  // pins
  digitalWrite(SWITCH_PIN, HIGH);
  pinMode(SWITCH_PIN, OUTPUT);

  // RNG
  Serial.println(F("Generating entropy."));
  RNG.begin(HOSTNAME, RNG_EEPROM_ADDR);
  // wait for some initial entropy
  while (!RNG.available(CHALLENGE_SIZE))
    RNG.loop();

  // Ethernet
  byte firmware_version = ether.begin(sizeof Ethernet::buffer, mac, ETHERNET_CS_PIN);
  Serial.print("Firmware version: ");
  Serial.println(firmware_version);
  if (firmware_version == 0)
  {
    Serial.println(F("Failed to access Ethernet controller"));
    fail();
  }
  ether.staticSetup(ip, gateway);
  ether.printIp("IP: ", ether.myip);
  ether.printIp("Gateway: ", ether.gwip);
}

static void to_hex(uint8_t *in, char *out, size_t nbytes) {
  for (int i = 0; i < nbytes; i++) {
    uint8_t upper = in[i] >> 4;
    out[2*i] = upper < 10 ? upper + '0' : upper - 10 + 'a';
    uint8_t lower = in[i] & 0xf;
    out[2*i+1] = lower < 10 ? lower + '0' : lower - 10 + 'a';
  }
  out[2*nbytes] = '\0';
}

static void from_hex(char *in, uint8_t *out, size_t nbytes) {
  for (int i = 0; i < nbytes; i++) {
    uint8_t upper = isalpha(in[2*i]) ? in[2*i] - 'a' + 10 : in[2*i] - '0';
    uint8_t lower = isalpha(in[2*i+1]) ? in[2*i+1] - 'a' + 10 : in[2*i+1] - '0';
    out[i] = upper << 4 | lower;
  }
}

static word handle_get_challenge() {
  long now = millis();
  if (challenge_valid && now - challenge_issued < CHALLENGE_EXPIRY) {
    Serial.println(F("Reusing challenge."));
  } else {
    Serial.print(F("Generating challenge: "));
    challenge_issued = now;
    challenge_valid = true;

    // This is sufficient (combined with the initial RNG seeding)
    // to ensure challenges have a very low probability of being reused
    // and also that the attacker cannot predict the next challenge.
    RNG.rand(challenge, sizeof(challenge));
    // This isn't really necessary, but just in case.
    sha256.reset();
    sha256.update(challenge, sizeof(challenge));
    sha256.finalize(challenge, sizeof(challenge));
    to_hex(challenge, challenge_hex, sizeof(challenge));

    Serial.println(challenge_hex);
  }

  bfill = ether.tcpOffset();
  bfill.emit_p(PSTR(
    "HTTP/1.1 200 OK\r\n"
    "Cache-Control: no-cache\r\n"
    "Content-Type: application/json\r\n"
    "\r\n"
    "{\"challenge\": \"$S\", \"salt\": \"" PASSWORD_SALT_HEX "\"}"
  ), challenge_hex);
  Serial.println(F("Request completed."));
  return bfill.position();
}

static void bad_request() {
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
  Serial.print(F("Pressing power button for "));
  Serial.print(press_length);
  Serial.println(F(" seconds."));
  digitalWrite(SWITCH_PIN, LOW);
  delay(press_length * 1000L);
  digitalWrite(SWITCH_PIN, HIGH);
  Serial.println(F("Unpressing power button."));
}

static word handle_post_reboot() {
  // compute expected hash
  sha256.reset();
  sha256.update(password_hash, sizeof(password_hash));
  sha256.update(challenge, sizeof(challenge));
  sha256.finalize(expected_hash, sizeof(expected_hash));

  char *remaining = rxdata + strlen(post_reboot_route);
  uint16_t remaining_len = rxdata_len - strlen(post_reboot_route);

  // check length
  if (remaining_len < sizeof(expected_hash)*2 + 3) {
    bad_request();
    return bfill.position();
  }

  // check against actual hash
  from_hex(remaining, actual_hash, sizeof(actual_hash));
  for (int i = 0; i < sizeof(expected_hash); i++) {
    if (actual_hash[i] != expected_hash[i]) {
      forbidden();
      return bfill.position();
    }
  }

  // check expiry
  long now = millis();
  if (!challenge_valid || now - challenge_issued >= CHALLENGE_EXPIRY) {
    Serial.println(F("Challenge invalid/expired."));
    forbidden();
    return bfill.position();
  }
  // invalidate challenge
  challenge_valid = false;

  // get the press length
  remaining += sizeof(expected_hash) * 2 + 1;
  remaining_len -= sizeof(expected_hash) * 2 + 1;
  if (remaining_len < 2) {
    bad_request();
    return bfill.position();
  }
  // read the length
  from_hex(remaining, &press_length, sizeof(press_length));

  bfill.emit_p(PSTR(
    "HTTP/1.1 204 No Content\r\n"
    "Cache-Control: no-cache\r\n"
    "\r\n"
  ));

  Serial.println(F("Request completed."));
  return bfill.position();
}

// requires a flash string
static bool match_route(const char *route) {
  int route_len = strlen_P(route);
  bool ret = rxdata_len >= route_len && strncmp_P(rxdata, route, route_len) == 0;
  if (ret) {
    Serial.print("Matched route ");
    Serial.println((const __FlashStringHelper *) route);
  }
  return ret;
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
    if (now - challenge_issued >= CHALLENGE_EXPIRY || now < challenge_issued) {
      challenge_valid = false;
    }

    // help the RNG a bit, but don't give it entropy credit
    RNG.stir((uint8_t *) &now, sizeof(now), 0);

    rxdata = (char *) Ethernet::buffer + pos;
    rxdata_len = len - pos;
    bfill = ether.tcpOffset();
    word txpos;
    if (match_route(get_challenge_route)) {
      txpos = handle_get_challenge();
    } else if (match_route(post_reboot_route)) {
      txpos = handle_post_reboot();
    } else {
      return;
    }
    ether.httpServerReply(txpos); // send web page data
    pos = 0;
  }

  if (press_length > 0) {
    reboot();
    press_length = 0;
  }
}

