-- SQL schema for secure party invitation application on MariaDB.

CREATE TABLE events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(150) NOT NULL UNIQUE,
    code_prefix CHAR(2) NOT NULL UNIQUE,
    description TEXT NULL,
    event_date DATETIME NOT NULL,
    invitation_text TEXT NOT NULL,
    background_image_url VARCHAR(512) NULL,
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
    user_agent VARCHAR(512),
    CONSTRAINT fk_access_event FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE,
    CONSTRAINT fk_access_guest FOREIGN KEY (guest_id) REFERENCES guests(id) ON DELETE CASCADE
);

-- Migration helper for bestehende Datenbanken
-- Führe diese Statements aus, um die neuen Spalten ohne Datenverlust hinzuzufügen:
-- ALTER TABLE events ADD COLUMN code_prefix CHAR(2) NOT NULL UNIQUE AFTER name;
-- ALTER TABLE events ADD COLUMN event_date DATETIME NOT NULL AFTER description;
-- ALTER TABLE events ADD COLUMN invitation_text TEXT NOT NULL AFTER event_date;
-- ALTER TABLE events ADD COLUMN background_image_url VARCHAR(512) NULL AFTER invitation_text;
