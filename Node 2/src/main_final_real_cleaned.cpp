// Dépendances platformio.ini :
// lib_deps = me-no-dev/AsyncTCP, me-no-dev/ESPAsyncWebServer
//
// Flags de compilation requis :
//   -DCONFIG_ASYNC_TCP_RUNNING_CORE=0
//   -DCONFIG_ASYNC_TCP_TASK_PRIORITY=3
//   -DCONFIG_ASYNC_TCP_QUEUE_SIZE=64
//   -DCONFIG_ASYNC_TCP_STACK_SIZE=8192

#include <WiFi.h>
#include <time.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <Preferences.h>
#include <map>
#include <vector>
#include <atomic>
#include <algorithm>
#include <freertos/semphr.h>

// ── Configuration réseau ──────────────────────────────────────────
const char* SSID     = "BaslimaneR";
const char* PASSWORD = "ishak2012";

#define UART_RX_PIN  16
#define UART_BAUD    115200

// ── Paramètres de détection DDoS ─────────────────────────────────
#define DDOS_WINDOW_MS       1000   // Durée de la fenêtre de comptage (ms)
#define DDOS_PPS_THRESHOLD   10     // Seuil de requêtes/s par IP avant bannissement
#define DDOS_GLOBAL_PPS_MAX  200    // Seuil global d'alerte trafic élevé
#define DDOS_TABLE_LIMIT     200    // Nombre maximum d'IP dans la table
#define CLEANUP_INTERVAL_MS  30000  // Intervalle de nettoyage de la table IP
#define BAN_LOG_THROTTLE_MS  1000   // Anti-spam des messages de bannissement
#define HEAP_LOG_INTERVAL_MS 10000  // Intervalle d'affichage de la mémoire libre

// ── Délais du chien de garde (watchdog) ──────────────────────────
#define ATTACK_REBOOT_MS     30000UL  // Redémarrage 30 s après la première détection d'attaque
#define WIFI_DEAD_REBOOT_MS 120000UL  // Redémarrage si le WiFi est mort depuis 2 min
#define WATCHDOG_CHECK_MS     1000UL  // Période de vérification du watchdog

// ── Configuration dual-core ───────────────────────────────────────
static constexpr uint32_t    NET_TASK_STACK           = 6144;  // Taille de la pile de la tâche réseau
static constexpr UBaseType_t NET_TASK_PRIO            = 5;     // Priorité de la tâche réseau
static constexpr BaseType_t  NET_TASK_CORE            = 0;     // Exécution sur le cœur 0
static constexpr uint32_t    NET_TASK_DELAY_MS        = 2;     // Délai de bouclage de la tâche réseau
static constexpr uint32_t    APP_LOOP_DELAY_MS        = 5;     // Délai de la boucle principale
static constexpr uint32_t    WIFI_RETRY_MS            = 5000;  // Délai entre tentatives de reconnexion WiFi
static constexpr uint32_t    LUX_HISTORY_INTERVAL_MS  = 15000; // Intervalle d'enregistrement de l'historique lux
static constexpr uint32_t    BANNED_SEND_MS           = 5000;  // Intervalle d'envoi de la liste des IP bannies
static constexpr uint16_t    LUX_HISTORY_MAX          = 100;   // Nombre maximum d'entrées dans l'historique

// ── Serveur web avec filtre TCP au niveau connexion ───────────────
// Bloque les IP bannies avant même de créer la requête HTTP,
// en s'accrochant au callback de nouvelle connexion d'AsyncTCP.
class TcpGateWebServer : public AsyncWebServer {
public:
    using GateFn = bool (*)(const String& ip);

    explicit TcpGateWebServer(uint16_t port) : AsyncWebServer(port) {}

    void setGate(GateFn fn) { _gate = fn; }

    void begin() {
        _server.onClient([](void* s, AsyncClient* c) {
            auto* self = static_cast<TcpGateWebServer*>(s);
            if (!c) return;

            // Fermer immédiatement les connexions bannies au niveau TCP
            if (self->_gate && self->_gate(c->remoteIP().toString())) {
                c->onDisconnect([](void*, AsyncClient* client) {
                    delete client;
                }, nullptr);
                c->close(true);
                return;
            }

            c->setRxTimeout(3);
            AsyncWebServerRequest* r = new AsyncWebServerRequest(self, c);
            if (r == nullptr) {
                c->onDisconnect([](void*, AsyncClient* client) {
                    delete client;
                }, nullptr);
                c->close(true);
            }
        }, this);

        AsyncWebServer::begin();
    }

private:
    GateFn _gate = nullptr;
};

// ── Variables d'état globales ─────────────────────────────────────
TcpGateWebServer server(80);
AsyncEventSource events("/events");

std::atomic<float> currentLux{0.0f};  // Dernière valeur de luminosité reçue
std::atomic<bool>  luxUpdated{false}; // Indicateur de nouvelle mesure disponible

// État de suivi par adresse IP (fenêtre glissante + bannissement)
struct IpState {
    uint32_t      pps;
    unsigned long windowStart;
    unsigned long bannedUntil;
};

std::map<String, IpState> ipTable;              // Table des états par IP
static SemaphoreHandle_t  tableMutex = nullptr; // Mutex de protection de la table IP

// Entrée d'historique de luminosité (valeur, timestamp Unix, indicateur de boot précédent)
struct LuxEntry { float value; uint32_t secs; bool prevBoot; };
static std::vector<LuxEntry> luxHistory;
static SemaphoreHandle_t     historyMutex = nullptr;

uint32_t      globalPps      = 0;       // Compteur de requêtes dans la fenêtre courante
unsigned long globalWinStart = 0;       // Début de la fenêtre globale
std::atomic<uint32_t> globalPeakPps{0}; // Pic de requêtes/s observé

unsigned long lastCleanupMs = 0;        // Horodatage du dernier nettoyage de table

std::atomic<uint32_t> lastLogMs{0};     // Horodatage du dernier log de bannissement (anti-spam)

// État du chien de garde
std::atomic<unsigned long> attackStartMs{0}; // Début de l'attaque en cours (0 = aucune)
std::atomic<unsigned long> lastWifiOkMs{0};  // Dernière fois que le WiFi était connecté

static TaskHandle_t netTaskHandle = nullptr; // Handle de la tâche réseau

// ── Persistance NVS (mémoire non-volatile) ────────────────────────
static Preferences nvs;
#define NVS_HIST_NAMESPACE  "lhist"

// Sauvegarde les 100 dernières entrées de l'historique dans la NVS
static void saveLuxHistory() {
    xSemaphoreTake(historyMutex, portMAX_DELAY);
    nvs.begin(NVS_HIST_NAMESPACE, false);
    nvs.clear();
    uint16_t total = (uint16_t)luxHistory.size();
    uint16_t start = total > LUX_HISTORY_MAX ? total - LUX_HISTORY_MAX : 0;
    uint16_t saved = 0;
    for (uint16_t i = start; i < total; ++i) {
        char vk[8], tk[8];
        snprintf(vk, sizeof(vk), "v%u", saved);
        snprintf(tk, sizeof(tk), "t%u", saved);
        nvs.putFloat(vk, luxHistory[i].value);
        nvs.putULong(tk, luxHistory[i].secs);
        ++saved;
    }
    nvs.putUShort("n", saved);
    nvs.end();
    xSemaphoreGive(historyMutex);
    Serial.printf("[NVS] %u entrées d'historique sauvegardées\n", saved);
}

// Restaure l'historique depuis la NVS au démarrage
static void loadLuxHistory() {
    nvs.begin(NVS_HIST_NAMESPACE, true);
    uint16_t count = nvs.getUShort("n", 0);
    xSemaphoreTake(historyMutex, portMAX_DELAY);
    for (uint16_t i = 0; i < count; ++i) {
        char vk[8], tk[8];
        snprintf(vk, sizeof(vk), "v%u", i);
        snprintf(tk, sizeof(tk), "t%u", i);
        luxHistory.push_back({nvs.getFloat(vk, 0.0f), nvs.getULong(tk, 0), true});
    }
    xSemaphoreGive(historyMutex);
    nvs.end();
    Serial.printf("[NVS] %u entrées d'historique restaurées\n", count);
}

// ── Chien de garde attaque ────────────────────────────────────────
// Enregistre l'horodatage du premier blocage ; les appels suivants sont ignorés
// pour que le minuteur de 30 s ne soit pas réinitialisé par l'activité continue.
static void markAttackActivity(unsigned long now) {
    unsigned long expected = 0;
    attackStartMs.compare_exchange_strong(expected, now,
        std::memory_order_relaxed, std::memory_order_relaxed);
}

// Déclenche un redémarrage si l'attaque dure depuis plus de ATTACK_REBOOT_MS
static void runAttackWatchdog(unsigned long now) {
    unsigned long start = attackStartMs.load(std::memory_order_relaxed);
    if (start == 0) return;

    if (now - start >= ATTACK_REBOOT_MS) {
        Serial.printf("[!!!] Attaque détectée depuis %lu ms — sauvegarde et redémarrage\n", now - start);
        Serial.flush();
        saveLuxHistory();
        delay(100);
        ESP.restart();
    }
}

// ── Anti-spam des logs de bannissement ───────────────────────────
static bool shouldLog(uint32_t nowMs) {
    uint32_t last = lastLogMs.load(std::memory_order_relaxed);
    if (nowMs - last < BAN_LOG_THROTTLE_MS) return false;
    return lastLogMs.compare_exchange_strong(
        last, nowMs, std::memory_order_relaxed, std::memory_order_relaxed);
}

// Applique un bannissement permanent (durée de session) à une entrée IP
// Appelant doit détenir tableMutex
static inline void applyBan(IpState& s) {
    s.bannedUntil = ULONG_MAX;
    s.pps         = 0;
}

// ── Moteur de détection et limitation de débit ────────────────────
// Retourne false si l'IP est bannie ou dépasse le seuil de requêtes/s
bool checkAndRate(const String& ip) {
    const unsigned long now = millis();

    xSemaphoreTake(tableMutex, portMAX_DELAY);

    auto it = ipTable.find(ip);
    if (it != ipTable.end()) {
        // IP déjà bannie : refus immédiat
        if (it->second.bannedUntil && it->second.bannedUntil > now) {
            xSemaphoreGive(tableMutex);
            markAttackActivity(now);
            return false;
        }
    } else if (ipTable.size() >= DDOS_TABLE_LIMIT) {
        // Table pleine : refus pour protéger la mémoire
        xSemaphoreGive(tableMutex);
        markAttackActivity(now);
        return false;
    }

    // Mise à jour du compteur global de requêtes par fenêtre
    bool globalWarn = false;
    uint32_t globalWarnPps = 0;
    if (now - globalWinStart >= DDOS_WINDOW_MS) {
        uint32_t cur = globalPps;
        if (cur > globalPeakPps.load(std::memory_order_relaxed))
            globalPeakPps.store(cur, std::memory_order_relaxed);
        if (cur >= DDOS_GLOBAL_PPS_MAX) {
            globalWarn    = true;
            globalWarnPps = cur;
        }
        globalPps      = 0;
        globalWinStart = now;
    }
    ++globalPps;

    // Mise à jour du compteur par IP
    IpState& s = (it != ipTable.end()) ? it->second : ipTable[ip];
    if (now - s.windowStart >= DDOS_WINDOW_MS) {
        s.windowStart = now;
        s.pps         = 0;
    }
    ++s.pps;

    bool banned = (s.pps > DDOS_PPS_THRESHOLD);
    if (banned) applyBan(s);

    xSemaphoreGive(tableMutex);

    if (globalWarn && shouldLog(now))
        Serial.printf("[DDoS] Global %u PPS >= %u — alerte trafic élevé\n",
                      globalWarnPps, DDOS_GLOBAL_PPS_MAX);
    if (banned) {
        markAttackActivity(now);
        if (shouldLog(now))
            Serial.printf("[DDoS] BANNI %s (session)\n", ip.c_str());
        return false;
    }
    return true;
}

// Vérifie si une IP est actuellement bannie (utilisé par le filtre TCP)
bool gateShouldBlock(const String& ip) {
    const unsigned long now = millis();
    xSemaphoreTake(tableMutex, portMAX_DELAY);

    auto it = ipTable.find(ip);
    if (it == ipTable.end()) {
        xSemaphoreGive(tableMutex);
        return false;
    }
    if (it->second.bannedUntil && it->second.bannedUntil > now) {
        xSemaphoreGive(tableMutex);
        markAttackActivity(now);
        return true;
    }
    xSemaphoreGive(tableMutex);
    return false;
}

// Supprime les entrées inactives et non-bannies de la table IP
void cleanupIpTable() {
    const unsigned long now = millis();
    xSemaphoreTake(tableMutex, portMAX_DELAY);
    for (auto it = ipTable.begin(); it != ipTable.end(); ) {
        bool banned = (it->second.bannedUntil > now);
        bool idle   = (now - it->second.windowStart > 30000);
        it = (!banned && idle) ? ipTable.erase(it) : std::next(it);
    }
    size_t sz = ipTable.size();
    xSemaphoreGive(tableMutex);
    Serial.printf("[DDoS] Table: %u entrées | pic: %u PPS | heap: %u\n",
                  (unsigned)sz,
                  globalPeakPps.load(std::memory_order_relaxed),
                  (unsigned)ESP.getFreeHeap());
}

// ── Gestion de la connexion WiFi ─────────────────────────────────
// Une inondation peut bloquer le pilote WiFi de façon irrémédiable ;
// un redémarrage propre après WIFI_DEAD_REBOOT_MS est le seul remède fiable.
bool ensureWifi() {
    static unsigned long lastTryMs = 0;
    const unsigned long now = millis();

    if (WiFi.status() == WL_CONNECTED) {
        lastWifiOkMs.store(now, std::memory_order_relaxed);
        return true;
    }

    // Redémarrage d'urgence si le WiFi est perdu trop longtemps
    unsigned long lastOk = lastWifiOkMs.load(std::memory_order_relaxed);
    if (lastOk > 0 && now - lastOk > WIFI_DEAD_REBOOT_MS) {
        Serial.printf("[!!!] WiFi perdu depuis %lu ms — sauvegarde et redémarrage\n", now - lastOk);
        Serial.flush();
        saveLuxHistory();
        delay(100);
        ESP.restart();
    }

    if (now - lastTryMs < WIFI_RETRY_MS) return false;
    lastTryMs = now;

    Serial.println("[WiFi] Déconnecté, reconnexion…");
    WiFi.disconnect();
    WiFi.begin(SSID, PASSWORD);
    return false;
}

// ── Middleware de limitation de débit HTTP ────────────────────────
// Intercepte toutes les requêtes : bloque les IP bannies ou au-dessus du seuil
class RateLimitMiddleware : public AsyncWebHandler {
public:
    bool canHandle(AsyncWebServerRequest* req) const override {
        AsyncClient* c = req->client();
        if (!c) return false;
        const String ip = c->remoteIP().toString();
        if (gateShouldBlock(ip)) return true;
        return !checkAndRate(ip);
    }

    void handleRequest(AsyncWebServerRequest* req) override {
        AsyncWebServerResponse* resp = req->beginResponse(429, "text/plain", "Too Many Requests");
        resp->addHeader("Connection", "close");
        req->send(resp);
    }
};

// ── Construction des payloads SSE ─────────────────────────────────

// Sérialise l'historique de luminosité en JSON pour l'envoi SSE
static String buildHistoryJson() {
    xSemaphoreTake(historyMutex, portMAX_DELAY);
    String json = "[";
    for (size_t i = 0; i < luxHistory.size(); ++i) {
        if (i) json += ',';
        json += "{\"v\":";
        json += String(luxHistory[i].value, 1);
        json += ",\"t\":";
        json += luxHistory[i].secs;
        json += ",\"p\":";
        json += luxHistory[i].prevBoot ? '1' : '0';
        json += '}';
    }
    json += ']';
    xSemaphoreGive(historyMutex);
    return json;
}

// Sérialise la liste des IP bannies en JSON pour l'envoi SSE
static String buildBannedJson() {
    const unsigned long now = millis();
    xSemaphoreTake(tableMutex, portMAX_DELAY);
    String json = "[";
    bool first = true;
    for (auto& kv : ipTable) {
        if (kv.second.bannedUntil > now) {
            if (!first) json += ',';
            json += '"';
            json += kv.first;
            json += '"';
            first = false;
        }
    }
    json += ']';
    xSemaphoreGive(tableMutex);
    return json;
}

// ── Page web embarquée ────────────────────────────────────────────
const char INDEX_HTML[] PROGMEM = R"rawhtml(
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Light Sensor</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: sans-serif; background: #111; color: #eee;
           display: flex; flex-direction: column; align-items: center;
           min-height: 100vh; margin: 0; padding: 2rem 1rem; }
    h1   { font-size: 1.2rem; opacity: .6; margin-bottom: .5rem; }
    #lux { font-size: 5rem; font-weight: 700; color: #ffd54f; }
    #unit{ font-size: 1.5rem; opacity: .5; }
    #status { margin-top: 1rem; font-size: .85rem; opacity: .4; }
    .panel { margin-top: 2rem; border-top: 1px solid #333; padding-top: 1.5rem;
             width: 100%; max-width: 420px; }
    .panel-title { font-size: .8rem; letter-spacing: .08em; text-transform: uppercase;
                   opacity: .5; margin-bottom: .75rem; text-align: center; }
    .hist-list { max-height: 220px; overflow-y: auto; }
    .hist-entry { display: grid; grid-template-columns: 2rem 1fr auto;
                  align-items: center; gap: .5rem;
                  padding: .3rem .5rem; border-bottom: 1px solid #222; font-size: .9rem; }
    .hist-idx  { opacity: .35; font-size: .75rem; }
    .hist-time { font-size: .8rem; opacity: .55; font-variant-numeric: tabular-nums; }
    .hist-entry.prev { opacity: .45; font-style: italic; }
    .hist-val { color: #ffd54f; font-weight: 600; }
    .hist-sep { text-align: center; font-size: .75rem; opacity: .35;
                padding: .4rem; border-bottom: 1px solid #222; }
    .hist-empty { text-align: center; opacity: .3; font-size: .85rem; padding: .5rem; }
    .banned-list { font-size: .875rem; }
    .banned-ip { color: #ff5252; padding: .25rem .5rem; border-bottom: 1px solid #1a1a1a; }
    .banned-none { text-align: center; opacity: .3; font-size: .85rem; padding: .5rem; }
  </style>
</head>
<body>
  <h1>BH1750 Light Sensor</h1>
  <div><span id="lux">—</span><span id="unit"> lx</span></div>
  <div id="status">Waiting for data…</div>

  <div class="panel">
    <div class="panel-title">Lux History (every 15 s)</div>
    <div id="hist-list" class="hist-list">
      <div class="hist-empty">No readings yet</div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-title">Banned IPs</div>
    <div id="banned-list" class="banned-list">
      <div class="banned-none">None</div>
    </div>
  </div>

  <script>
    setTimeout(() => location.reload(), 30000);

    const src = new EventSource('/events');
    let reloadTimer = null;

    src.addEventListener('lux', e => {
      document.getElementById('lux').textContent = parseFloat(e.data).toFixed(1);
      const st = document.getElementById('status');
      st.textContent = 'Last update: ' + new Date().toLocaleTimeString();
      st.style.color = '';
      st.style.opacity = '.4';
      st.style.fontSize = '.85rem';
      st.style.fontWeight = 'normal';
      if (reloadTimer) { clearTimeout(reloadTimer); reloadTimer = null; }
    });

    function fmtTime(t, prevBoot) {
      if (!t) return '—';
      const d = new Date(t * 1000);
      return prevBoot ? d.toLocaleString() : d.toLocaleTimeString();
    }

    src.addEventListener('history', e => {
      const entries = JSON.parse(e.data);
      const list = document.getElementById('hist-list');
      list.innerHTML = '';
      if (!entries.length) {
        list.innerHTML = '<div class="hist-empty">No readings yet</div>';
        return;
      }
      let sepShown = false;
      for (let i = entries.length - 1; i >= 0; i--) {
        const en = entries[i];
        if (!sepShown && en.p) {
          const sep = document.createElement('div');
          sep.className = 'hist-sep';
          sep.textContent = '— previous boot —';
          list.appendChild(sep);
          sepShown = true;
        }
        const div = document.createElement('div');
        div.className = 'hist-entry' + (en.p ? ' prev' : '');
        div.innerHTML = '<span class="hist-idx">' + (i + 1) + '</span>' +
                        '<span class="hist-time">' + fmtTime(en.t, en.p) + '</span>' +
                        '<span class="hist-val">' + Number(en.v).toFixed(1) + ' lx</span>';
        list.appendChild(div);
      }
    });

    src.addEventListener('banned', e => {
      const ips = JSON.parse(e.data);
      const el = document.getElementById('banned-list');
      if (!ips.length) {
        el.innerHTML = '<div class="banned-none">None</div>';
      } else {
        el.innerHTML = ips.map(ip => '<div class="banned-ip">' + ip + '</div>').join('');
      }
    });

    src.onerror = () => {
      const st = document.getElementById('status');
      st.textContent = 'CONNECTION LOST! Retrying...';
      st.style.color = '#ff5252';
      st.style.opacity = '1';
      st.style.fontSize = '1.5rem';
      st.style.fontWeight = 'bold';
      if (!reloadTimer) {
        reloadTimer = setTimeout(() => location.reload(), 60000);
      }
    };
  </script>
</body>
</html>
)rawhtml";

// ── Tâche réseau (cœur 0, priorité supérieure à AsyncTCP) ─────────
// Gère en parallèle : reconnexion WiFi, watchdog, nettoyage table,
// surveillance mémoire, et diffusion des événements SSE.
void netTask(void* arg) {
    (void)arg;
    unsigned long lastHeapMs     = millis();
    unsigned long lastWatchdogMs = millis();
    unsigned long lastHistoryMs  = millis();
    unsigned long lastBannedMs   = millis();

    for (;;) {
        unsigned long now = millis();

        // Attendre la reconnexion WiFi avant de traiter quoi que ce soit
        if (!ensureWifi()) {
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }

        // Nettoyage périodique des entrées inactives de la table IP
        if (now - lastCleanupMs >= CLEANUP_INTERVAL_MS) {
            lastCleanupMs = now;
            cleanupIpTable();
        }

        // Vérification du chien de garde anti-attaque
        if (now - lastWatchdogMs >= WATCHDOG_CHECK_MS) {
            lastWatchdogMs = now;
            runAttackWatchdog(now);
        }

        // Rapport périodique de la mémoire heap disponible
        if (now - lastHeapMs >= HEAP_LOG_INTERVAL_MS) {
            lastHeapMs = now;
            Serial.printf("[mem] heap libre=%u min=%u\n",
                          (unsigned)ESP.getFreeHeap(),
                          (unsigned)ESP.getMinFreeHeap());
        }

        // Diffusion de la nouvelle valeur de luminosité via SSE
        if (luxUpdated.exchange(false, std::memory_order_acquire)) {
            float lux = currentLux.load(std::memory_order_relaxed);
            events.send(String(lux, 2).c_str(), "lux", millis());
        }

        // Enregistrement et diffusion de l'historique toutes les 15 s
        if (now - lastHistoryMs >= LUX_HISTORY_INTERVAL_MS) {
            lastHistoryMs = now;
            float lux = currentLux.load(std::memory_order_relaxed);
            xSemaphoreTake(historyMutex, portMAX_DELAY);
            if (luxHistory.size() >= LUX_HISTORY_MAX)
                luxHistory.erase(luxHistory.begin());
            luxHistory.push_back({lux, (uint32_t)time(nullptr), false});
            xSemaphoreGive(historyMutex);
            saveLuxHistory();
            events.send(buildHistoryJson().c_str(), "history", millis());
        }

        // Diffusion périodique de la liste des IP bannies
        if (now - lastBannedMs >= BANNED_SEND_MS) {
            lastBannedMs = now;
            events.send(buildBannedJson().c_str(), "banned", millis());
        }

        vTaskDelay(pdMS_TO_TICKS(NET_TASK_DELAY_MS));
    }
}

// ── Initialisation (exécutée une seule fois au démarrage) ─────────
void setup() {
    Serial.begin(115200);
    Serial2.begin(UART_BAUD, SERIAL_8N1, UART_RX_PIN, -1);

    Serial.printf("\n[Boot] Raison du redémarrage : %d\n", (int)esp_reset_reason());

    // Création des mutex pour la table IP et l'historique
    tableMutex = xSemaphoreCreateMutex();
    if (!tableMutex) {
        Serial.println("[ERR] Échec de création du mutex table");
        while (true) delay(1000);
    }
    historyMutex = xSemaphoreCreateMutex();
    if (!historyMutex) {
        Serial.println("[ERR] Échec de création du mutex historique");
        while (true) delay(1000);
    }

    loadLuxHistory();

    // Connexion au réseau WiFi
    WiFi.setAutoReconnect(true);
    WiFi.persistent(true);
    WiFi.mode(WIFI_STA);
    WiFi.setSleep(false);
    WiFi.begin(SSID, PASSWORD);
    Serial.print("Connexion");
    while (WiFi.status() != WL_CONNECTED) { Serial.print('.'); delay(500); }
    Serial.printf("\nIP : %s\n", WiFi.localIP().toString().c_str());

    // Synchronisation de l'horloge via NTP
    configTime(0, 0, "pool.ntp.org", "time.nist.gov");
    Serial.print("Synchro NTP");
    struct tm tmInfo;
    while (!getLocalTime(&tmInfo, 0)) { Serial.print('.'); delay(200); }
    Serial.println(" OK");

    lastWifiOkMs.store(millis(), std::memory_order_relaxed);
    globalWinStart = millis();

    // Configuration du serveur web avec filtre anti-DDoS
    server.setGate(gateShouldBlock);
    server.addHandler(new RateLimitMiddleware());

    server.on("/", HTTP_GET, [](AsyncWebServerRequest* req) {
        req->send(200, "text/html", INDEX_HTML);
    });

    server.onNotFound([](AsyncWebServerRequest* req) {
        req->send(404);
    });

    // Envoi de l'historique et des bannissements à chaque nouvelle connexion SSE
    events.onConnect([](AsyncEventSourceClient* client) {
        client->send(buildHistoryJson().c_str(), "history", millis(), 0);
        client->send(buildBannedJson().c_str(), "banned", millis(), 0);
    });

    server.addHandler(&events);
    server.begin();

    // Lancement de la tâche réseau sur le cœur 0
    BaseType_t ok = xTaskCreatePinnedToCore(
        netTask, "netTask", NET_TASK_STACK, nullptr, NET_TASK_PRIO, &netTaskHandle, NET_TASK_CORE);
    if (ok != pdPASS)
        Serial.println("[ERR] Échec du lancement de netTask");
}

// ── Boucle principale (cœur 1) ────────────────────────────────────
// Lit les trames LUX depuis l'UART et met à jour la valeur partagée
// pour que la tâche réseau puisse la diffuser via SSE.
void loop() {
    while (Serial2.available()) {
        String line = Serial2.readStringUntil('\n');
        line.trim();
        if (line.startsWith("LUX:")) {
            float lux = line.substring(4).toFloat();
            currentLux.store(lux, std::memory_order_relaxed);
            luxUpdated.store(true, std::memory_order_release);
            Serial.printf("[UART] lux=%.2f\n", lux);
        }
    }

    delay(APP_LOOP_DELAY_MS);
}
