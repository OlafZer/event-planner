-- SQL schema for secure party invitation application on MariaDB.

CREATE TABLE event (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(150) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE admin_user (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    totp_secret VARCHAR(32) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'event_admin',
    event_id INT NULL,
    CONSTRAINT fk_admin_event FOREIGN KEY (event_id) REFERENCES event(id) ON DELETE SET NULL
);

CREATE TABLE guest_unit (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_id INT NOT NULL,
    name VARCHAR(120) NOT NULL,
    invite_code CHAR(8) NOT NULL,
    max_persons INT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'safe_the_date',
    confirmed_persons INT NOT NULL DEFAULT 0,
    email VARCHAR(255),
    notify_admin TINYINT(1) NOT NULL DEFAULT 0,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_guest_event FOREIGN KEY (event_id) REFERENCES event(id) ON DELETE CASCADE,
    CONSTRAINT uq_event_code UNIQUE (event_id, invite_code)
);

CREATE TABLE access_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_id INT NOT NULL,
    guest_unit_id INT NOT NULL,
    accessed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_agent VARCHAR(255),
    CONSTRAINT fk_access_event FOREIGN KEY (event_id) REFERENCES event(id) ON DELETE CASCADE,
    CONSTRAINT fk_access_guest FOREIGN KEY (guest_unit_id) REFERENCES guest_unit(id) ON DELETE CASCADE
);

-- Seed example super admin (password hash must be generated securely in Python).
INSERT INTO admin_user (email, password_hash, totp_secret, role)
VALUES ('admin@example.com', '<hashed_password_here>', '<totp_secret_here>', 'super_admin');
