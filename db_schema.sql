-- Mandantenfähige Event-Anmelde-Datenbank (MariaDB-kompatibel)
-- Alle Tabellen besitzen einen strikten Bezug zu event_id, um Isolation zu gewährleisten.

CREATE TABLE events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, -- Eindeutige Event-ID
    name VARCHAR(255) NOT NULL, -- Klartextname des Events
    status ENUM('Safe the Date', 'Zusage', 'Absage', 'Unsicher') NOT NULL DEFAULT 'Safe the Date', -- Aktueller Status des Events (fixe Optionsmenge)
    starts_at DATETIME NULL, -- Optionale Startzeit
    ends_at DATETIME NULL, -- Optionale Endzeit
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- Erstellungstimestamp
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP -- Änderungszeitpunkt
);

CREATE TABLE admins (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, -- Admin-ID
    email VARCHAR(255) NOT NULL UNIQUE, -- Login-E-Mail
    password_hash VARCHAR(255) NOT NULL, -- Gehashter Passwort-Hash (z. B. PBKDF2/bcrypt)
    role ENUM('super_admin', 'event_admin') NOT NULL DEFAULT 'event_admin', -- Rollen-Hierarchie
    assigned_event_id BIGINT UNSIGNED NULL, -- Zugewiesenes Event für Event-Admins (NULL für Super-Admins)
    totp_secret VARCHAR(64) NOT NULL, -- Secret für TOTP-basierte 2FA
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_admin_event FOREIGN KEY (assigned_event_id) REFERENCES events(id) ON DELETE SET NULL
);

CREATE TABLE guest_units (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, -- ID pro Einladungseinheit (Familie/Paar)
    event_id BIGINT UNSIGNED NOT NULL, -- Fremdschlüssel zur Sicherstellung der Mandantenbindung
    invite_code CHAR(8) NOT NULL, -- Achtstelliger Zugangscode
    max_attendees INT NOT NULL DEFAULT 1, -- Maximale Personenanzahl für diese Einheit
    status ENUM('Safe the Date', 'Zusage', 'Absage', 'Unsicher') NOT NULL DEFAULT 'Safe the Date', -- Fester Status-Satz
    final_attendees INT NULL, -- Final gemeldete Personenanzahl bei Zusage
    primary_contact_name VARCHAR(255) NULL, -- Optionaler Name für Übersicht
    notify_admin BOOLEAN NOT NULL DEFAULT FALSE, -- Steuert E-Mail-Benachrichtigung bei Statusänderung
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_code_per_event (event_id, invite_code), -- Code darf pro Event nur einmal vorkommen
    CONSTRAINT fk_guest_event FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
);

CREATE TABLE access_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, -- Log-ID
    event_id BIGINT UNSIGNED NOT NULL, -- Zuordnung zum Event für Auswertungen
    invite_code CHAR(8) NOT NULL, -- Mitverfolgter Code für die Einheit
    accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- Zeitpunkt des Seitenaufrufs
    user_agent VARCHAR(512) NULL, -- Optional: User-Agent zur Analyse
    ip_address VARCHAR(45) NULL, -- Optional: IPv4/IPv6
    CONSTRAINT fk_log_event FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
);

-- Indexe zur Performance-Optimierung
CREATE INDEX idx_guest_event_status ON guest_units (event_id, status);
CREATE INDEX idx_log_event_code ON access_logs (event_id, invite_code);
