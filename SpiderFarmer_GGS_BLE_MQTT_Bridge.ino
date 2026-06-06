#include <WiFi.h>
#include <PubSubClient.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <BLE2902.h> 

// --- KONFIGURATION ---
#ifndef WIFI_SSID
#define WIFI_SSID ""
#endif
#ifndef WIFI_PASSWORD
#define WIFI_PASSWORD ""
#endif
#ifndef MQTT_SERVER
#define MQTT_SERVER ""
#endif
#ifndef MQTT_PORT
#define MQTT_PORT 1883
#endif
#ifndef MQTT_USER
#define MQTT_USER ""
#endif
#ifndef MQTT_PASS
#define MQTT_PASS ""
#endif
#ifndef MQTT_TOPIC_PREFIX
#define MQTT_TOPIC_PREFIX "grow/GGS"
#endif
#ifndef GGS_BLE_ADDRESS
#define GGS_BLE_ADDRESS "78:5e:1a:6b:56:2a"
#endif

const char* ssid = WIFI_SSID;
const char* password = WIFI_PASSWORD;

const char* mqtt_server = MQTT_SERVER;
const int mqtt_port = MQTT_PORT;

const char* mqtt_user = MQTT_USER;
const char* mqtt_pass = MQTT_PASS;

String ble_address = GGS_BLE_ADDRESS;     // Die MAC deines GGS Controllers

// UUID für Notifications
static BLEUUID charNotifyUUID("0000ff01-0000-1000-8000-00805f9b34fb");

// Globale Objekte
WiFiClient espClient;
PubSubClient mqttClient(espClient);
BLEClient* pClient = NULL;
BLERemoteCharacteristic* pRemoteCharacteristic;
bool connected = false;
String jsonBuffer = "";
String mqttTopicPrefix = MQTT_TOPIC_PREFIX;

String topicPath(const char* suffix) {
  return mqttTopicPrefix + "/" + suffix;
}

// --- HILFSFUNKTION: Robustes Parsen mit Offset ---
// Diese Funktion ignoriert "Müll-Zeichen" zwischen den Werten
String extractValueAfter(String json, String parentKey, String targetKey) {
  // 1. Suche den Startbereich (z.B. "fan":)
  int parentPos = json.indexOf("\"" + parentKey + "\":");
  if (parentPos == -1) return ""; 

  // 2. Suche den Ziel-Schlüssel AB dieser Position
  int targetPos = json.indexOf("\"" + targetKey + "\":", parentPos);
  if (targetPos == -1) return "";

  // Sicherheits-Check: Wenn der Abstand zu groß ist, abbrechen
  if (targetPos - parentPos > 200) return "";

  // 3. Wert extrahieren (hinter "key":)
  int startValue = targetPos + targetKey.length() + 3; // +3 für ": und "
  int endValue = startValue;
  
  // Suche das Ende der Zahl (Komma oder Klammer zu)
  while (endValue < json.length()) {
    char c = json[endValue];
    if (c == ',' || c == '}' || c == ']') break;
    endValue++;
  }
  
  // Bereinigen
  String result = json.substring(startValue, endValue);
  result.replace("\"", ""); 
  return result;
}

// Hilfsfunktion für MQTT Debugging
void sendMqtt(const char* topicSuffix, String value) {
    if (value == "") return;
    String topic = topicPath(topicSuffix);
    
    if (mqttClient.publish(topic.c_str(), value.c_str())) {
        Serial.print(" [MQTT OK] "); 
    } else {
        Serial.print(" [MQTT ERR state=");
        Serial.print(mqttClient.state()); 
        Serial.print("] ");
    }
    Serial.print(topic.c_str());
    Serial.print(": ");
    Serial.println(value);
}

void processRawData(String rawData) {
  // Wir prüfen grob ob "sensor" drin vorkommt, um leere Puffer zu vermeiden
  if (rawData.indexOf("\"sensor\"") == -1) return;

  Serial.println("\n--- VERARBEITE DATEN ---");

  // --- SENSOREN ---
  String sTemp = extractValueAfter(rawData, "sensor", "temp");
  String sHumi = extractValueAfter(rawData, "sensor", "humi");
  String sVpd  = extractValueAfter(rawData, "sensor", "vpd");

  if(sTemp != "") sendMqtt("sensor/temp", sTemp);
  if(sHumi != "") sendMqtt("sensor/humi", sHumi);
  if(sVpd != "")  sendMqtt("sensor/vpd", sVpd);

  // --- LÜFTER (Fan) ---
  String sFanLvl = extractValueAfter(rawData, "fan", "level");
  String sFanOn  = extractValueAfter(rawData, "fan", "on");

  if(sFanLvl != "") sendMqtt("fan/level", sFanLvl);
  if(sFanOn != "")  sendMqtt("fan/on", sFanOn);

  // --- BLOWER ---
  String sBlowerLvl = extractValueAfter(rawData, "blower", "level");
  if(sBlowerLvl != "") sendMqtt("blower/level", sBlowerLvl);

  // --- LICHT (Light) ---
  String sLightLvl = extractValueAfter(rawData, "light", "level");
  String sLightOn  = extractValueAfter(rawData, "light", "on");
  
  if(sLightLvl != "") sendMqtt("light/level", sLightLvl);
  if(sLightOn != "")  sendMqtt("light/on", sLightOn);
  
  Serial.println("------------------------");
}

static void notifyCallback(
  BLERemoteCharacteristic* pBLERemoteCharacteristic,
  uint8_t* pData,
  size_t length,
  bool isNotify) {
    
    for (int i = 0; i < length; i++) {
        char c = (char)pData[i];
        // Nur ASCII Zeichen sammeln (filtert Header-Müll)
        if (c >= 32 && c <= 126) {
            jsonBuffer += c;
        }
    }

    // TRIGGER LOGIK: Warten bis "fan" und schließende Klammern da sind
    if (jsonBuffer.indexOf("fan\"") > 0 && jsonBuffer.indexOf("}}") > 0) {
       processRawData(jsonBuffer);
       jsonBuffer = ""; 
    }
    
    // Notfall Reset falls Buffer überläuft
    if (jsonBuffer.length() > 2500) jsonBuffer = "";
}

class MyClientCallback : public BLEClientCallbacks {
  void onConnect(BLEClient* pclient) {
    Serial.println(">>> BLE VERBUNDEN! Setze MTU 517...");
    pclient->setMTU(517); 
    connected = true;
  }
  void onDisconnect(BLEClient* pclient) {
    Serial.println(">>> BLE GETRENNT!");
    connected = false;
  }
};

bool connectToBLE() {
    Serial.print("BLE Suche: "); Serial.println(ble_address);
    
    BLEClient* pClient = BLEDevice::createClient();
    pClient->setClientCallbacks(new MyClientCallback());

    if (!pClient->connect(BLEAddress(ble_address.c_str()))) {
        Serial.println("BLE Connect Failed");
        return false;
    }
    delay(100); 

    BLERemoteService* pRemoteService = nullptr;
    std::map<std::string, BLERemoteService*>* services = pClient->getServices();
    
    for (auto const& [uuid, service] : *services) {
        pRemoteCharacteristic = service->getCharacteristic(charNotifyUUID);
        if (pRemoteCharacteristic != nullptr) break;
    }

    if (pRemoteCharacteristic == nullptr) {
        pClient->disconnect();
        return false;
    }

    if(pRemoteCharacteristic->canNotify()) {
        pRemoteCharacteristic->registerForNotify(notifyCallback);
        // WICHTIG: Manuelles Aktivieren der Notifications via CCCD
        BLERemoteDescriptor* p2902 = pRemoteCharacteristic->getDescriptor(BLEUUID((uint16_t)0x2902));
        if(p2902 != nullptr) {
            uint8_t val[] = {0x01, 0x00};
            p2902->writeValue(val, 2, true);
            Serial.println("CCCD gesetzt!");
        }
    }
    return true;
}

void setupWifi() {
  if (String(ssid).length() == 0 || String(password).length() == 0) {
    Serial.println("WLAN Zugangsdaten fehlen (WIFI_SSID/WIFI_PASSWORD).");
    return;
  }
  Serial.print("Verbinde WLAN");
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
  Serial.println(" OK");
}

void reconnectMqtt() {
  if (!mqttClient.connected()) {
    if (String(mqtt_server).length() == 0) {
      Serial.println("MQTT_SERVER fehlt.");
      delay(2000);
      return;
    }
    Serial.print("MQTT Verbinde...");
    String statusTopic = topicPath("status");
    bool mqttConnected = false;
    if (String(mqtt_user).length() == 0) {
      mqttConnected = mqttClient.connect(
        "ESP32_GGS_Bridge",
        statusTopic.c_str(),
        1,
        true,
        "offline"
      );
    } else {
      mqttConnected = mqttClient.connect(
        "ESP32_GGS_Bridge",
        mqtt_user,
        mqtt_pass,
        statusTopic.c_str(),
        1,
        true,
        "offline"
      );
    }
    if (mqttConnected) {
      
      Serial.println(" OK");
      mqttClient.publish(statusTopic.c_str(), "online", true);
      
    } else {
      Serial.print(" Fehler rc=");
      Serial.println(mqttClient.state());
      // Kurze Pause vor dem nächsten Versuch
      delay(2000);
    }
  }
}

void setup() {
  Serial.begin(115200);
  setupWifi();
  mqttClient.setServer(mqtt_server, mqtt_port);
  // Puffer erhöhen für lange Payloads
  mqttClient.setBufferSize(512);
  mqttClient.setKeepAlive(30);
  BLEDevice::init("");
}

void loop() {
  if (!mqttClient.connected()) reconnectMqtt();
  mqttClient.loop(); // Wichtig für MQTT Datenverkehr

  if (!connected) {
     static unsigned long lastTry = 0;
     if(millis() - lastTry > 10000) {
        lastTry = millis();
        connectToBLE();
     }
  }
  delay(50);
}
