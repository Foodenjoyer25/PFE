#include <Arduino.h>
#include <Wire.h>
#include <BH1750.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SH110X.h>

// ── Pin config ───────────────────────────────────────
#define SDA_PIN          8
#define SCL_PIN          9
#define UART_TX_PIN      17

// ── Display ──────────────────────────────────────────
#define SCREEN_W         128
#define SCREEN_H         64
#define OLED_ADDR        0x3C
#define OLED_RESET       -1

// ── Timing ───────────────────────────────────────────
#define READ_INTERVAL_MS   200
#define SEND_INTERVAL_MS  1000

Adafruit_SH1106G display(SCREEN_W, SCREEN_H, &Wire, OLED_RESET);
BH1750 lightMeter;

// ── UI ───────────────────────────────────────────────
void drawUI(float lux, bool txActive) {
  display.clearDisplay();

  // Header bar
  display.fillRect(0, 0, SCREEN_W, 12, SH110X_WHITE);
  display.setTextColor(SH110X_BLACK);
  display.setTextSize(1);
  display.setCursor(4, 2);
  display.print("BH1750  Light Sensor");

  // Lux value — large, centered
  display.setTextColor(SH110X_WHITE);
  display.setTextSize(2);

  char luxBuf[14];
  if (lux < 0)
    snprintf(luxBuf, sizeof(luxBuf), "ERR");
  else if (lux >= 10000)
    snprintf(luxBuf, sizeof(luxBuf), "%.0f lx", lux);
  else
    snprintf(luxBuf, sizeof(luxBuf), "%.1f lx", lux);

  int16_t tx, ty;
  uint16_t tw, th;
  display.getTextBounds(luxBuf, 0, 0, &tx, &ty, &tw, &th);
  display.setCursor((SCREEN_W - tw) / 2, 20);
  display.print(luxBuf);

  // Condition label
  display.setTextSize(1);
  const char* condition;
  if      (lux < 0)     condition = "Sensor error";
  else if (lux < 10)    condition = "Very dark";
  else if (lux < 200)   condition = "Dim / indoor";
  else if (lux < 1000)  condition = "Well lit";
  else if (lux < 10000) condition = "Bright";
  else                   condition = "Direct sunlight";

  display.getTextBounds(condition, 0, 0, &tx, &ty, &tw, &th);
  display.setCursor((SCREEN_W - tw) / 2, 44);
  display.print(condition);

  // Bottom status bar
  display.drawLine(0, 55, SCREEN_W, 55, SH110X_WHITE);
  display.setTextSize(1);
  display.setTextColor(SH110X_WHITE);
  display.setCursor(4, 57);
  display.print(txActive ? "TX >" : "TX  ");
  display.setCursor(36, 57);
  display.printf("%.0f lx raw", lux < 0 ? 0.0f : lux);

  display.display();
}

// ── Setup ─────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  Serial1.begin(115200, SERIAL_8N1, -1, UART_TX_PIN);

  Wire.begin(SDA_PIN, SCL_PIN);

  // OLED — same init as working reference
  if (!display.begin(OLED_ADDR, true)) {
    Serial.println("[OLED] Init failed — check wiring");
    while (true) delay(1000);
  }

  display.clearDisplay();
  display.setTextColor(SH110X_WHITE);
  display.setTextSize(1);
  display.setCursor(24, 28);
  display.print("Initializing...");
  display.display();
  delay(800);

  // BH1750
  if (!lightMeter.begin(BH1750::CONTINUOUS_HIGH_RES_MODE)) {
    Serial.println("[BH1750] Init failed — check wiring");
    display.clearDisplay();
    display.setCursor(4, 28);
    display.print("BH1750 error!");
    display.display();
    while (true) delay(1000);
  }

  Serial.println("[OK] Node A ready");
}

// ── Loop ─────────────────────────────────────────────
void loop() {
  static unsigned long lastRead = 0;
  static unsigned long lastSend = 0;
  static float lux = 0.0f;
  static bool txActive = false;

  const unsigned long now = millis();

  // Read sensor
  if (now - lastRead >= READ_INTERVAL_MS) {
    lastRead = now;
    if (lightMeter.measurementReady()) {
      lux = lightMeter.readLightLevel();
      if (lux < 0) Serial.println("[BH1750] Bad reading");
      else         Serial.printf("[BH1750] %.2f lx\n", lux);
    }
    txActive = false;
  }

  // Send over UART
  if (now - lastSend >= SEND_INTERVAL_MS) {
    lastSend = now;
    if (lux >= 0) {
      Serial1.printf("LUX:%.2f\n", lux);
      Serial.printf("[UART] Sent LUX:%.2f\n", lux);
      txActive = true;
    }
  }

  drawUI(lux, txActive);
}