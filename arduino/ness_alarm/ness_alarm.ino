const int LED_PIN = 8;
const int BUZZER_PIN = 9;
const char* PROTOCOL_ID = "NESS_ALARM_V1";

void pulseAlert(int times, int toneHz, int delayMs) {
  for (int i = 0; i < times; i++) {
    digitalWrite(LED_PIN, HIGH);
    tone(BUZZER_PIN, toneHz);
    delay(delayMs);
    digitalWrite(LED_PIN, LOW);
    noTone(BUZZER_PIN);
    delay(delayMs);
  }
}

void setup() {
  pinMode(LED_PIN, OUTPUT);
  pinMode(BUZZER_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);
  noTone(BUZZER_PIN);
  Serial.begin(9600);
  Serial.setTimeout(100);
  delay(250);
  Serial.print("NESS_READY:");
  Serial.println(PROTOCOL_ID);
}

void loop() {
  if (Serial.available() <= 0) return;

  String command = Serial.readStringUntil('\n');
  command.trim();
  command.toUpperCase();

  if (command == "PING") {
    Serial.print("PONG:");
    Serial.println(PROTOCOL_ID);
    return;
  }

  if (command == "CRITICAL") {
    Serial.println("ACK:CRITICAL");
    pulseAlert(6, 1500, 180);
  } else if (command == "ALERT") {
    Serial.println("ACK:ALERT");
    pulseAlert(3, 1000, 220);
  } else if (command == "TEST") {
    Serial.println("ACK:TEST");
    pulseAlert(2, 1200, 160);
  } else if (command == "OFF") {
    Serial.println("ACK:OFF");
    digitalWrite(LED_PIN, LOW);
    noTone(BUZZER_PIN);
  } else {
    Serial.println("ERR:UNKNOWN_COMMAND");
  }
}
