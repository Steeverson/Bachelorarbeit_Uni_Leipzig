# Bachelorarbeit - Readme

## Voraussetzungen:
- Arch Linux Virtuelle Maschine
- Auf VM Suricata installiert
- Auf VM Docker installiert

Alternativ kann eine vorbereitete OVA Datei unter: 
heruntergeladen werden. Diese ist vorkonfiguriert und kann in Virtual Box importiert werden.

## Vorbereitung Suricata

Innerhalb der Datei /etc/suricata/suricata.yaml:
- unter **vars** -> **port-groups** einfügen:
  - RTSP_PORTS: "[554,8554]"
- unter **rule-files**:
  -   Auskommentieren: - suricata.rules
  -   Auskommentieren: - local.rules
  -   Hinzufügen: - ba_custom.rules

## Start der Testumgebung:
Innerhalb des Projektordners: 
> sudo sh ./startup.sh

## Stoppen der Testumgebung:
Innerhalb des Projektordners:
> sudo sh ./teardown.sh

## Starten von Suricata:
> sudo suricata -i br-smarthome

## Starten der Angriffssimulation
> sudo python ./ba_attack_runner_min.py attacks_v2_min.json

Output der Angriffssimulation zu finden unter:
- attack_runs/yyyymmdd_hhmmss/run.log
- attack_runs/yyyymmdd_hhmmss/run_report.json

## Starten des Skripts zu Filterung von Suricata Regeln auf Smart-Home-Relevanz:
> python3 ba_filter_rules.py <input_dir> <output_rules_file
wobei:
- input_dir das Verzeichnis ist, in dem die zu filternen Rulefiles abgelegt wurden
- output_rules_file das Verzeichnis ist, in dem die zusammengesetzte Rulefile abgelegt werden soll


## Starten des Skripts zum Überwachen von Paketdrops durch Suricata:
> python monitor_drops.py

## Starten des Noise Skripts zu simulation von Netzwerkrauschen und prüfen auf False Positives
> python ba_noise.py
