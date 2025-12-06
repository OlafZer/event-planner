-- SQL schema for secure party invitation application on MariaDB.

CREATE TABLE events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(150) NOT NULL UNIQUE,
    description TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE admin_user (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    totp_secret VARCHAR(32) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'event_admin',
    event_id BIGINT UNSIGNED NULL,
    CONSTRAINT fk_admin_event FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE SET NULL
);

CREATE TABLE guests (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    event_id BIGINT UNSIGNED NOT NULL,
    first_name VARCHAR(150) NOT NULL,
    last_name VARCHAR(150) NULL,
    category VARCHAR(50) NOT NULL,
    max_persons INT NOT NULL DEFAULT 1,
    invite_code_hash CHAR(64) NOT NULL UNIQUE,
    email VARCHAR(255) NULL,
    telephone VARCHAR(50) NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'safe_the_date',
    confirmed_persons INT NOT NULL DEFAULT 0,
    notes TEXT NULL,
    notify_admin TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_guests_event FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
);

CREATE TABLE access_log (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    event_id BIGINT UNSIGNED NOT NULL,
    guest_id BIGINT UNSIGNED NOT NULL,
    accessed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_agent VARCHAR(255),
    CONSTRAINT fk_access_event FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE,
    CONSTRAINT fk_access_guest FOREIGN KEY (guest_id) REFERENCES guests(id) ON DELETE CASCADE
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
    CONSTRAINT fk_admins_assigned_event FOREIGN KEY (assigned_event_id) REFERENCES events(id) ON DELETE SET NULL
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
    CONSTRAINT fk_guest_units_event FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
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
