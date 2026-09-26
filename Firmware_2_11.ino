/*
 * LoRa-Based Decentralized Network System
 * Firmware Version: 2.11
 *
 * Basic System Configuration:
 *   - Microcontroller: Raspberry Pi Pico
 *   - LoRa Module: SX1278
 *
 * Description:
 *   This firmware is designed for a decentralized communication
 *   network using LoRa-based wireless communication.
 */



#include <SPI.h>
#include <LoRa.h>
#include <Crypto.h>

#include <GCM.h>   
#include <AES.h>     // Embedded Galois/Counter Mode cipher engine
#include <string.h>
#include <EEPROM.h>
#include <Curve25519.h> 

#define SECURE_NET_ID 0x42 

#define MY_NODE_ID   3
#define MY_NODE_PASSWORD "3333" 

bool bleAuthenticated = false;
unsigned long authTime = 0;
#define AUTH_TIMEOUT 30000000    // 5 minutes

#define SS    8
#define RST   9
#define DIO0  10
#define SCK   2
#define MISO  4
#define MOSI  3
#define BLE Serial1

#define MAX_HOPS          5
#define MAX_SEEN_PACKETS  50

// --- EXTENDED PROTOCOL PACKET TYPES ---
#define TYPE_TEXT       1
#define TYPE_ACK        2
#define TYPE_ECDH_REQ   3
#define TYPE_ECDH_RESP  4
#define TYPE_RREQ       5
#define TYPE_RREP       6
#define TYPE_HELLO      7
#define TYPE_RERR       8

// --- MESH & RELIABILITY CONFIG ---
#define MAX_QUEUE_SIZE 30
#define RETRY_TIMEOUT_MS 3000 
#define MAX_RETRIES 5

#define MAX_NODES 30
#define MAX_ROUTES 30
#define ROUTE_TIMEOUT_MS 300000 // 5 Minutes Route Lifetime

#define HELLO_INTERVAL_MS 10000 // 10 seconds
#define NEIGHBOR_TIMEOUT_MS 30000 // 30 seconds

// --- AES-256-GCM Cipher Definition ---
GCM<AES256> gcmEngine; 
uint8_t groupKey[32] = {
    0x7A,0x3F,0xC2,0x91,0x58,0xB4,0xDE,0x17,
    0x63,0xAF,0x29,0x80,0xD5,0x44,0x11,0x98,
    0xBE,0x36,0xF7,0xCA,0x02,0x5D,0xE9,0x70,
    0x13,0x8B,0x4E,0xA1,0x95,0xCC,0x61,0x2F
};

// --- ANTI-REPLAY WINDOW CONFIG ---
#define REPLAY_WINDOW_SIZE 32

// --- CRYPTO STATE VARIABLES ---
uint8_t myPrivateKey[32];
uint8_t myPublicKey[32];
uint32_t mySequenceNumber = 0; 

enum NodeStatus { UNVERIFIED, BLACKLISTED, WHITELISTED };

struct NodeEntry {
  uint8_t id;
  uint8_t sessionKey[32];      // 256-bit secret key space
  uint32_t lastSeqNum;         // Top edge of anti-replay sliding window
  uint32_t replayWindowBitmask;// Bitmask tracking structural reception space
  NodeStatus status;
};

struct RouteEntry {
  uint8_t dest;
  uint8_t nextHop;
  uint8_t hops;
  unsigned long lastUsed;
};

struct SeenPacket {
  uint8_t src;
  uint8_t id;
};

struct QueuedMessage {
  bool active;
  uint8_t dest;
  uint8_t id;
  uint8_t retryCount;
  unsigned long lastAttempt;
  char payload[64]; 
};

struct NeighborEntry {
  uint8_t id;
  unsigned long lastHeard;
};

#define MAX_NEIGHBORS 10

// Global Memory Tables
NodeEntry nodeTable[MAX_NODES];
RouteEntry routeTable[MAX_ROUTES];
SeenPacket seen[MAX_SEEN_PACKETS];
uint16_t seenCursor = 0; // Circular buffer tracking cursor
uint8_t msgID = 0;
QueuedMessage txQueue[MAX_QUEUE_SIZE];
NeighborEntry neighborTable[MAX_NEIGHBORS];
unsigned long lastHelloTime = 0;

String bleBuffer = "";
String serialBuffer = "";

// Forward Declarations
void sendEncryptedPacket(uint8_t from, uint8_t to, uint8_t nextHop, uint8_t type, uint8_t packetId, String payload, uint8_t* key);
void initiateRREQ(uint8_t targetDest);
void sendECDHRequest(uint8_t targetNode);
void sendECDHResponse(uint8_t targetNode);
NodeEntry* getNode(uint8_t id);
NodeEntry* addNode(uint8_t id, NodeStatus status);
RouteEntry* getRoute(uint8_t dest);
void updateRoute(uint8_t dest, uint8_t nextHop, uint8_t hops);
bool alreadySeen(uint8_t src, uint8_t id);
void markSeen(uint8_t src, uint8_t id);
void logboth(String s);
void handleFromPhone(String input);
void processQueue();
void handleLoRa();
bool checkAndUpdateAntiReplay(NodeEntry* node, uint32_t incomingSeq);

void saveQueue();
void invalidateRoute(uint8_t dest);
void sendRERR(uint8_t unreachableDest);
void sendHello();
void updateNeighbor(uint8_t id);
void checkNeighborTimeout();

void setup() {
  Serial.begin(115200);

  #if defined(ARDUINO_ARCH_RP2040) || defined(ESP8266) || defined(ESP32)
  EEPROM.begin(1024);
  #endif

  // Dynamic seed generator pulling localized system floor entropy
  uint32_t runningSeed = 0;
  for(int i=0; i<16; i++) {
    runningSeed = (runningSeed << 2) | (analogRead(26) & 3);
    delayMicroseconds(50);
  }
  randomSeed(runningSeed);

  for (int i = 0; i < 32; i++) {
    myPrivateKey[i] = random(0, 256);
  }
  Curve25519::eval(myPublicKey, myPrivateKey, NULL); 

  // Initialize Operational Node Tables
  for (int i = 0; i < MAX_NODES; i++) {
    nodeTable[i].id = 0;
    nodeTable[i].lastSeqNum = 0;
    nodeTable[i].replayWindowBitmask = 0;
  }
  for (int i = 0; i < MAX_ROUTES; i++) routeTable[i].dest = 0;
  for (int i = 0; i < MAX_NEIGHBORS; i++) neighborTable[i].id = 0;
  for (int i = 0; i < MAX_SEEN_PACKETS; i++) { seen[i].src = 0; seen[i].id = 0; }

  // System Queue Configurations From Local Flash Storage
  EEPROM.get(0, txQueue);
  bool queueCorrupt = false;
  for(int i = 0; i < MAX_QUEUE_SIZE; i++) {
    if (txQueue[i].active && (txQueue[i].dest == 0xFF || txQueue[i].dest == 0 || txQueue[i].retryCount > MAX_RETRIES)) {
      txQueue[i].active = false;
      queueCorrupt = true;
    }
    if(txQueue[i].active) {
      txQueue[i].lastAttempt = millis() - (RETRY_TIMEOUT_MS + 500); 
    }
  }
  if (queueCorrupt) {
    saveQueue();
  }

  BLE.begin(9600);
  delay(1000);
  BLE.println("AT");
  delay(300);
  BLE.println("AT+NAME=Node" + String(MY_NODE_ID));
  delay(300);

  SPI.setSCK(SCK);
  SPI.setTX(MOSI);
  SPI.setRX(MISO);
  SPI.begin();

  LoRa.setSPI(SPI);
  LoRa.setPins(SS, RST, DIO0);

  if (!LoRa.begin(433E6)) {
    Serial.println("LoRa FAILED");
    while (1);
  }

  LoRa.setTxPower(17);
  LoRa.setSpreadingFactor(10);
  LoRa.setSignalBandwidth(125E3);
  LoRa.setCodingRate4(5);
  LoRa.enableCrc();

  logboth("");
  logboth("=================================");
  logboth("LoRa AES-256-GCM MESH ONLINE");
  logboth("NODE ID: " + String(MY_NODE_ID));
  logboth("=================================");
}

void loop() {
  if (bleAuthenticated && (millis() - authTime > AUTH_TIMEOUT)) {
    bleAuthenticated = false;
    logboth("APP_STATUS:AUTH_TIMEOUT");
  }

  while (BLE.available()) {
    char c = BLE.read();
    if (c == '\n') {
      bleBuffer.trim();
      if (bleBuffer.length() > 0) handleFromPhone(bleBuffer);
      bleBuffer = "";
    } else {
      bleBuffer += c;
    }
  }

  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n') {
      serialBuffer.trim();
      if (serialBuffer.length() > 0) handleFromPhone(serialBuffer);
      serialBuffer = "";
    } else {
      serialBuffer += c;
    }
  }

  int packetSize = LoRa.parsePacket();
  if (packetSize > 0) {
    handleLoRa();
  }

  processQueue();

  unsigned long now = millis();
  if (now - lastHelloTime >= HELLO_INTERVAL_MS) {
    lastHelloTime = now;
    sendHello();
  }
  checkNeighborTimeout();
}

void handleFromPhone(String input) {
  if (input.startsWith("AUTH:")) {
    String pwd = input.substring(5); 
    if (pwd == MY_NODE_PASSWORD) {
      bleAuthenticated = true;
      authTime = millis(); 
      logboth("APP_STATUS:AUTH_SUCCESS");
    } else {
      logboth("APP_STATUS:AUTH_FAILED_INCORRECT_PASSWORD");
    }
    return; 
  }

  if (!bleAuthenticated) {
    logboth("APP_STATUS:AUTH_REQUIRED");
    return; 
  }

  authTime = millis(); 

  int colon = input.indexOf(':');
  if (colon == -1) {
    logboth("FORMAT ERROR");
    return;
  }

  uint8_t dest = input.substring(0, colon).toInt();
  String msg = input.substring(colon + 1);

  if (dest == MY_NODE_ID) return;
  if (dest == 0) dest = 0xFF; 

  uint8_t currentMsgID = msgID++;
  
  if (dest == 0xFF) {
    sendEncryptedPacket(
      MY_NODE_ID,
      0xFF,
      0xFF,
      TYPE_TEXT,
      currentMsgID,
      msg,
      groupKey
    );
    logboth("APP_STATUS:" + String(currentMsgID) + ":SENT");
    return;
  }

  bool queued = false;
  for(int i = 0; i < MAX_QUEUE_SIZE; i++) {
    if(!txQueue[i].active) {
      txQueue[i].active = true;
      txQueue[i].dest = dest;
      txQueue[i].id = currentMsgID;
      txQueue[i].retryCount = 0;
      txQueue[i].lastAttempt = millis() - 4000; 
      strncpy(txQueue[i].payload, msg.c_str(), 63);
      txQueue[i].payload[63] = '\0';
      
      saveQueue();
      logboth("APP_STATUS:" + String(currentMsgID) + ":SENT"); 
      queued = true;
      break;
    }
  }

  if(!queued) {
    logboth("APP_STATUS:" + String(currentMsgID) + ":FAILED_QUEUE_FULL");
  }
}

void processQueue() {
  unsigned long now = millis();
  bool queueChanged = false;

  for(int i = 0; i < MAX_QUEUE_SIZE; i++) {
    if(txQueue[i].active) {
      unsigned long timeout = RETRY_TIMEOUT_MS * (1 << txQueue[i].retryCount);
      
      if (now - txQueue[i].lastAttempt >= timeout) {
        txQueue[i].lastAttempt = now;
        
        NodeEntry* node = getNode(txQueue[i].dest);
        RouteEntry* route = getRoute(txQueue[i].dest);
        
        if (!node) {
          sendECDHRequest(txQueue[i].dest);
          txQueue[i].retryCount++;
        }
        else if (!route) {
          initiateRREQ(txQueue[i].dest);
          txQueue[i].retryCount++;
        }
        else {
          sendEncryptedPacket(MY_NODE_ID, txQueue[i].dest, route->nextHop, TYPE_TEXT, txQueue[i].id, String(txQueue[i].payload), node->sessionKey);
          txQueue[i].retryCount++;
          logboth("SENDING ENCRYPTED GCM MSG ID:" + String(txQueue[i].id) + " VIA NEXT_HOP:" + String(route->nextHop));
        }

        if (txQueue[i].retryCount > MAX_RETRIES) {
          txQueue[i].active = false;
          queueChanged = true;
          logboth("APP_STATUS:" + String(txQueue[i].id) + ":FAILED_NO_ACK");
          invalidateRoute(txQueue[i].dest); 
        }
      }
    }
  }

  if (queueChanged) {
    saveQueue();
  }
}

// --- STRUCTURAL SLIDING WINDOW CHECK FOR ANTI-REPLAY ---
bool checkAndUpdateAntiReplay(NodeEntry* node, uint32_t incomingSeq) {
  if (incomingSeq == 0) return false; // Prevent dynamic zero resets

  if (incomingSeq > node->lastSeqNum) {
    // Forward evolution of tracking window
    uint32_t delta = incomingSeq - node->lastSeqNum;
    if (delta < REPLAY_WINDOW_SIZE) {
      node->replayWindowBitmask = (node->replayWindowBitmask << delta) | 1;
    } else {
      node->replayWindowBitmask = 1;
    }
    node->lastSeqNum = incomingSeq;
    return true;
  }
  
  // Checking inside historical sequence floor space
  uint32_t delta = node->lastSeqNum - incomingSeq;
  if (delta >= REPLAY_WINDOW_SIZE) {
    return false; // Packet falls completely outside sliding window bounds
  }
  
  if (node->replayWindowBitmask & ((uint32_t)1 << delta)) {
    return false; // Bit position matches an already processed packet ID
  }
  
  node->replayWindowBitmask |= ((uint32_t)1 << delta); // Trace missing index
  return true;
}

void handleLoRa() {
  if (LoRa.available() < 6) return; 

  uint8_t incomingNetID = LoRa.read(); 
  if (incomingNetID != SECURE_NET_ID) return;

  uint8_t from    = LoRa.read();
  uint8_t to      = LoRa.read();
  uint8_t nextHop = LoRa.read();
  uint8_t type    = LoRa.read();
  uint8_t packetId = LoRa.read();

  updateNeighbor(from);

  if (to != 0xFF && nextHop != MY_NODE_ID && nextHop != 0xFF) {
    return;
  }

  if (type == TYPE_HELLO) return; 

  if (type == TYPE_RERR) {
    if (LoRa.available() > 0) {
      uint8_t unreachableDest = LoRa.read();
      RouteEntry* route = getRoute(unreachableDest);
      if (route && route->nextHop == from) {
        invalidateRoute(unreachableDest);
        sendRERR(unreachableDest);
      }
    }
    return; 
  }

  if (type == TYPE_ECDH_REQ || type == TYPE_ECDH_RESP) {
    if (LoRa.available() < 32) return;
    uint8_t remotePubKey[32];
    LoRa.readBytes(remotePubKey, 32);

    if (to == MY_NODE_ID) {
      NodeEntry* node = getNode(from);
      if (!node) node = addNode(from, WHITELISTED);

      if (node && node->status != BLACKLISTED) {
        Curve25519::eval(node->sessionKey, myPrivateKey, remotePubKey);
        node->status = WHITELISTED;
        
        // Context tracking clean alignment step
        node->lastSeqNum = 0; 
        node->replayWindowBitmask = 0;
        if (type == TYPE_ECDH_REQ) {
          mySequenceNumber = 0; 
          sendECDHResponse(from);
        }
        Serial.println("GCM SECURE CONTEXT RESET & SYNCHRONIZED WITH NODE: " + String(from));
      }
    } else {
      RouteEntry* path = getRoute(to);
      if (path) {
        LoRa.beginPacket();
        LoRa.write(SECURE_NET_ID);
        LoRa.write(from); 
        LoRa.write(to);   
        LoRa.write(path->nextHop); 
        LoRa.write(type);
        LoRa.write(packetId);
        LoRa.write(remotePubKey, 32);
        LoRa.endPacket();
      } else {
        sendRERR(to);
      }
    }
    return; 
  }

  if (type == TYPE_RREQ) {
    if (LoRa.available() < 3) return;
    uint8_t originator = LoRa.read();
    uint8_t target = LoRa.read();
    uint8_t hops = LoRa.read();

    if (alreadySeen(originator, packetId)) return;
    markSeen(originator, packetId);

    updateRoute(originator, from, hops + 1); 

    if (target == MY_NODE_ID) {
      RouteEntry* revRoute = getRoute(originator);
      if (revRoute) {
        LoRa.beginPacket();
        LoRa.write(SECURE_NET_ID);
        LoRa.write(MY_NODE_ID);
        LoRa.write(originator);
        LoRa.write(revRoute->nextHop);
        LoRa.write(TYPE_RREP);
        LoRa.write((uint8_t)random(0, 256));
        LoRa.write(MY_NODE_ID); 
        LoRa.write((uint8_t)0); 
        LoRa.endPacket();
        Serial.println("AODV ENGINE: Replying with RREP to Node " + String(originator));
      }
    } else if (hops < MAX_HOPS) {
      delay(random(40, 150)); 
      LoRa.beginPacket();
      LoRa.write(SECURE_NET_ID);
      LoRa.write(MY_NODE_ID); 
      LoRa.write((uint8_t)0xFF); 
      LoRa.write((uint8_t)0xFF); 
      LoRa.write(TYPE_RREQ);
      LoRa.write(packetId);
      LoRa.write(originator);
      LoRa.write(target);
      LoRa.write((uint8_t)(hops + 1));
      LoRa.endPacket();
    }
    return; 
  }

  if (type == TYPE_RREP) {
    if (LoRa.available() < 2) return;
    uint8_t originalTarget = LoRa.read();
    uint8_t hops = LoRa.read();

    updateRoute(originalTarget, from, hops + 1);

    if (to != MY_NODE_ID) {
      RouteEntry* revRoute = getRoute(to);
      if (revRoute) {
        LoRa.beginPacket();
        LoRa.write(SECURE_NET_ID);
        LoRa.write(MY_NODE_ID); 
        LoRa.write(to);
        LoRa.write(revRoute->nextHop);
        LoRa.write(TYPE_RREP);
        LoRa.write(packetId);
        LoRa.write(originalTarget);
        LoRa.write((uint8_t)(hops + 1));
        LoRa.endPacket();
      }
    }
    return; 
  }

  // --- COMPONENT 5: BROADCAST DECRYPT PIPELINE WITH ANTI-REPLAY ---
  if (to == 0xFF && type == TYPE_TEXT) {
    if (alreadySeen(from, packetId)) return;
    markSeen(from, packetId);

    if (LoRa.available() < 29) return; 

    uint8_t rxIv[12];
    uint8_t rxTag[16];
    LoRa.readBytes(rxIv, 12);
    LoRa.readBytes(rxTag, 16);
    uint8_t cipherTextLen = LoRa.read();
    
    if (LoRa.available() < cipherTextLen || cipherTextLen > 128) return; 

    uint8_t cipherBuffer[cipherTextLen];
    LoRa.readBytes(cipherBuffer, cipherTextLen);

    // Dynamic Tracking Entry validation block for broadcast entities
    NodeEntry* broadcastSenderNode = getNode(from);
    if (!broadcastSenderNode) {
      broadcastSenderNode = addNode(from, UNVERIFIED);
    }
    
    if (broadcastSenderNode) {
      uint32_t verificationSequence = 0;
      memcpy(&verificationSequence, rxIv, 4);
      if (!checkAndUpdateAntiReplay(broadcastSenderNode, verificationSequence)) {
        Serial.println("REPLAY BLOCKED: Broadcast sequence out of window alignment.");
        return;
      }
    }

    gcmEngine.setKey(groupKey, 32);
    gcmEngine.setIV(rxIv, 12);

    uint8_t headerAuthenticationBuffer[4] = { from, to, type, packetId };
    gcmEngine.addAuthData(headerAuthenticationBuffer, 4);

    uint8_t plainTextOutput[cipherTextLen + 1];
    gcmEngine.decrypt(plainTextOutput, cipherBuffer, cipherTextLen);
    plainTextOutput[cipherTextLen] = '\0'; 

    if (!gcmEngine.checkTag(rxTag, 16)) {
      Serial.println("TAMPER FAIL: Group GCM validation dropped.");
      return;
    }
    
    int rssi = LoRa.packetRssi();
    float snr = LoRa.packetSnr();
    uint8_t msgHops = 1; 

    String msgText = String((char*)plainTextOutput);
    String appFormat = "[FROM:" + String(from) + 
                       " TO:" + String(to) + 
                       " HOPS:" + String(msgHops) + 
                       " RSSI:" + String(rssi) + 
                       " SNR:" + String(snr, 1) + 
                       "] " + msgText;
    logboth(appFormat);
    return;
  }

  // --- UNICAST DECRYPT PIPELINE WITH SLIDING ANTI-REPLAY ---
  NodeEntry* node = getNode(from);
  if (!node || node->status != WHITELISTED) return;

  if (LoRa.available() < 29) return; 
  uint8_t rxIv[12];
  uint8_t rxTag[16];
  LoRa.readBytes(rxIv, 12);
  LoRa.readBytes(rxTag, 16);
  uint8_t cipherTextLen = LoRa.read();
  
  if (LoRa.available() < cipherTextLen || cipherTextLen > 128) return; 

  if (to != MY_NODE_ID) {
    RouteEntry* path = getRoute(to);
    uint8_t intermediateCipher[cipherTextLen];
    LoRa.readBytes(intermediateCipher, cipherTextLen);

    if (path) {
      LoRa.beginPacket();
      LoRa.write(SECURE_NET_ID);
      LoRa.write(from); 
      LoRa.write(to);   
      LoRa.write(path->nextHop); 
      LoRa.write(type);
      LoRa.write(packetId);
      LoRa.write(rxIv, 12);
      LoRa.write(rxTag, 16);
      LoRa.write(cipherTextLen);
      LoRa.write(intermediateCipher, cipherTextLen);
      LoRa.endPacket();
    } else {
      sendRERR(to);
    }
    return;
  }

  uint8_t cipherBuffer[cipherTextLen];
  LoRa.readBytes(cipherBuffer, cipherTextLen);

  uint32_t verificationSequence = 0;
  memcpy(&verificationSequence, rxIv, 4);
  
  // Execution of Sliding Window Replay Validation
  if (!checkAndUpdateAntiReplay(node, verificationSequence)) {
    Serial.println("REPLAY BLOCKED: Unicast sequence out of window alignment.");
    return;
  }

  gcmEngine.setKey(node->sessionKey, 32);
  gcmEngine.setIV(rxIv, 12);

  uint8_t headerAuthenticationBuffer[4] = { from, to, type, packetId };
  gcmEngine.addAuthData(headerAuthenticationBuffer, 4);

  uint8_t plainTextOutput[cipherTextLen + 1];
  gcmEngine.decrypt(plainTextOutput, cipherBuffer, cipherTextLen);
  plainTextOutput[cipherTextLen] = '\0'; 

  if (!gcmEngine.checkTag(rxTag, 16)) {
    Serial.println("TAMPER FAIL: GCM validation dropped.");
    return;
  }

  if (type == TYPE_ACK) {
    bool queueChanged = false;
    for(int i = 0; i < MAX_QUEUE_SIZE; i++) {
      if(txQueue[i].active && txQueue[i].dest == from && txQueue[i].id == packetId) {
        txQueue[i].active = false;
        queueChanged = true;
        logboth("APP_STATUS:" + String(packetId) + ":DELIVERED");
      }
    }
    if(queueChanged) saveQueue();
  } 
  else if (type == TYPE_TEXT) {
    if (alreadySeen(from, packetId)) {
      RouteEntry* ackPath = getRoute(from);
      if (ackPath) {
        sendEncryptedPacket(MY_NODE_ID, from, ackPath->nextHop, TYPE_ACK, packetId, "A", node->sessionKey);
      }
      return;
    }
    markSeen(from, packetId);
    
    int rssi = LoRa.packetRssi();
    float snr = LoRa.packetSnr();
    uint8_t msgHops = 1;
    
    RouteEntry* sourceRoute = getRoute(from);
    if (sourceRoute) {
      msgHops = sourceRoute->hops;
    }

    String msgText = String((char*)plainTextOutput);
    String appFormat = "[FROM:" + String(from) + 
                       " TO:" + String(to) + 
                       " HOPS:" + String(msgHops) + 
                       " RSSI:" + String(rssi) + 
                       " SNR:" + String(snr, 1) + 
                       "] " + msgText;
    logboth(appFormat);

    RouteEntry* ackPath = getRoute(from);
    if (ackPath) {
      sendEncryptedPacket(MY_NODE_ID, from, ackPath->nextHop, TYPE_ACK, packetId, "A", node->sessionKey);
    }
  }
}

void sendEncryptedPacket(uint8_t from, uint8_t to, uint8_t nextHop, uint8_t type, uint8_t packetId, String payload, uint8_t* key) {
  mySequenceNumber++; 

  uint8_t txIv[12];
  memset(txIv, 0, 12);
  uint32_t currentCounterState = mySequenceNumber;
  memcpy(txIv, &currentCounterState, 4); 
  for(int i = 4; i < 12; i++) {
    txIv[i] = random(0, 256); 
  }

  gcmEngine.setKey(key, 32);
  gcmEngine.setIV(txIv, 12);

  uint8_t headerAuthenticationBuffer[4] = { from, to, type, packetId };
  gcmEngine.addAuthData(headerAuthenticationBuffer, 4);

  int textLength = payload.length();
  uint8_t cipherTextOutput[textLength];
  gcmEngine.encrypt(cipherTextOutput, (const uint8_t*)payload.c_str(), textLength);

  uint8_t computedValidationTag[16];
  gcmEngine.computeTag(computedValidationTag, 16);

  LoRa.beginPacket();
  LoRa.write(SECURE_NET_ID);
  LoRa.write(from);
  LoRa.write(to); 
  LoRa.write(nextHop); 
  LoRa.write(type);
  LoRa.write(packetId);
  LoRa.write(txIv, 12);
  LoRa.write(computedValidationTag, 16);
  LoRa.write((uint8_t)textLength);
  LoRa.write(cipherTextOutput, textLength);
  LoRa.endPacket();
}

void sendECDHRequest(uint8_t targetNode) {
  RouteEntry* route = getRoute(targetNode);
  if (!route) {
    initiateRREQ(targetNode);
    return;
  }
  LoRa.beginPacket();
  LoRa.write(SECURE_NET_ID);
  LoRa.write(MY_NODE_ID);
  LoRa.write(targetNode);
  LoRa.write(route->nextHop); 
  LoRa.write((uint8_t)TYPE_ECDH_REQ);
  LoRa.write((uint8_t)random(0, 256));
  LoRa.write(myPublicKey, 32);
  LoRa.endPacket();
}

void sendECDHResponse(uint8_t targetNode) {
  RouteEntry* route = getRoute(targetNode);
  if (!route) {
    initiateRREQ(targetNode);
    return;
  }
  LoRa.beginPacket();
  LoRa.write(SECURE_NET_ID);
  LoRa.write(MY_NODE_ID);
  LoRa.write(targetNode);
  LoRa.write(route->nextHop); 
  LoRa.write((uint8_t)TYPE_ECDH_RESP);
  LoRa.write((uint8_t)random(0, 256));
  LoRa.write(myPublicKey, 32);
  LoRa.endPacket();
}

void initiateRREQ(uint8_t targetDest) {
  uint8_t rreqNonce = random(0, 256);
  LoRa.beginPacket();
  LoRa.write(SECURE_NET_ID);
  LoRa.write(MY_NODE_ID);
  LoRa.write((uint8_t)0xFF); 
  LoRa.write((uint8_t)0xFF); 
  LoRa.write((uint8_t)TYPE_RREQ);
  LoRa.write(rreqNonce); 
  LoRa.write(MY_NODE_ID); 
  LoRa.write(targetDest); 
  LoRa.write((uint8_t)0); 
  LoRa.endPacket();
}

NodeEntry* getNode(uint8_t id) {
  for (int i=0; i<MAX_NODES; i++) {
    if (nodeTable[i].id == id) return &nodeTable[i];
  }
  return nullptr;
}

NodeEntry* addNode(uint8_t id, NodeStatus status) {
  for (int i=0; i<MAX_NODES; i++) {
    if (nodeTable[i].id == 0) {
      nodeTable[i].id = id;
      nodeTable[i].status = status;
      nodeTable[i].lastSeqNum = 0;
      nodeTable[i].replayWindowBitmask = 0;
      return &nodeTable[i];
    }
  }
  return nullptr;
}

RouteEntry* getRoute(uint8_t dest) {
  for (int i=0; i<MAX_ROUTES; i++) {
    if (routeTable[i].dest == dest && (millis() - routeTable[i].lastUsed < ROUTE_TIMEOUT_MS)) {
      routeTable[i].lastUsed = millis(); 
      return &routeTable[i];
    }
  }
  return nullptr;
}

void updateRoute(uint8_t dest, uint8_t nextHop, uint8_t hops) {
  for (int i=0; i<MAX_ROUTES; i++) {
    if (routeTable[i].dest == dest) {
      if (hops <= routeTable[i].hops || (millis() - routeTable[i].lastUsed > ROUTE_TIMEOUT_MS)) {
        routeTable[i].nextHop = nextHop;
        routeTable[i].hops = hops;
        routeTable[i].lastUsed = millis();
      }
      return;
    }
  }
  for (int i=0; i<MAX_ROUTES; i++) {
    if (routeTable[i].dest == 0 || (millis() - routeTable[i].lastUsed > ROUTE_TIMEOUT_MS)) {
      routeTable[i].dest = dest;
      routeTable[i].nextHop = nextHop;
      routeTable[i].hops = hops;
      routeTable[i].lastUsed = millis();
      return;
    }
  }
}

bool alreadySeen(uint8_t src, uint8_t id) {
  for (int i = 0; i < MAX_SEEN_PACKETS; i++) {
    if (seen[i].src == src && seen[i].id == id) return true;
  }
  return false;
}

void markSeen(uint8_t src, uint8_t id) {
  seen[seenCursor].src = src;
  seen[seenCursor].id  = id;
  seenCursor = (seenCursor + 1) % MAX_SEEN_PACKETS;
}

void logboth(String s) {
  Serial.println(s);
  BLE.print(s);       
  BLE.print("\n");   
}

void saveQueue() {
  EEPROM.put(0, txQueue);
  #if defined(ARDUINO_ARCH_RP2040) || defined(ESP8266) || defined(ESP32)
  EEPROM.commit();
  #endif
}

void invalidateRoute(uint8_t dest) {
  for (int i = 0; i < MAX_ROUTES; i++) {
    if (routeTable[i].dest == dest) {
      routeTable[i].dest = 0;
      Serial.println("ROUTE INVALIDATED TO NODE: " + String(dest));
      break;
    }
  }
}

void sendRERR(uint8_t unreachableDest) {
  LoRa.beginPacket();
  LoRa.write(SECURE_NET_ID);
  LoRa.write(MY_NODE_ID);
  LoRa.write((uint8_t)0xFF); 
  LoRa.write((uint8_t)0xFF); 
  LoRa.write((uint8_t)TYPE_RERR);
  LoRa.write((uint8_t)0); 
  LoRa.write(unreachableDest);
  LoRa.endPacket();
}

void sendHello() {
  LoRa.beginPacket();
  LoRa.write(SECURE_NET_ID);
  LoRa.write(MY_NODE_ID);
  LoRa.write((uint8_t)0xFF); 
  LoRa.write((uint8_t)0xFF); 
  LoRa.write((uint8_t)TYPE_HELLO);
  LoRa.write((uint8_t)0); 
  LoRa.endPacket();
}

void updateNeighbor(uint8_t id) {
  if (id == MY_NODE_ID || id == 0xFF) return;
  unsigned long now = millis();
  for (int i = 0; i < MAX_NEIGHBORS; i++) {
    if (neighborTable[i].id == id) {
      neighborTable[i].lastHeard = now;
      return;
    }
  }
  for (int i = 0; i < MAX_NEIGHBORS; i++) {
    if (neighborTable[i].id == 0) {
      neighborTable[i].id = id;
      neighborTable[i].lastHeard = now;
      Serial.println("NEIGHBOR CONNECTED: Node " + String(id));
      return;
    }
  }
}

void checkNeighborTimeout() {
  unsigned long now = millis();
  for (int i = 0; i < MAX_NEIGHBORS; i++) {
    if (neighborTable[i].id != 0 && (now - neighborTable[i].lastHeard > NEIGHBOR_TIMEOUT_MS)) {
      uint8_t deadNeighbor = neighborTable[i].id;
      neighborTable[i].id = 0;
      Serial.println("NEIGHBOR TIMEOUT: Node " + String(deadNeighbor));
      
      for (int r = 0; r < MAX_ROUTES; r++) {
        if (routeTable[r].dest != 0 && routeTable[r].nextHop == deadNeighbor) {
          uint8_t unreachableDest = routeTable[r].dest;
          routeTable[r].dest = 0;
          sendRERR(unreachableDest);
        }
      }
    }
  }
}
