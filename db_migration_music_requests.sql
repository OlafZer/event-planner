-- Migration script to enable music request functionality for existing databases.
-- Execute with: mysql -h <host> -u <user> -p <database> < db_migration_music_requests.sql

ALTER TABLE events
    ADD COLUMN IF NOT EXISTS music_requests_enabled TINYINT(1) NOT NULL DEFAULT 0 AFTER background_image_url;

CREATE TABLE IF NOT EXISTS music_requests (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    event_id BIGINT UNSIGNED NOT NULL,
    guest_id BIGINT UNSIGNED NOT NULL,
    artist VARCHAR(255) NOT NULL,
    title VARCHAR(255) NOT NULL,
    spotify_track_id VARCHAR(255) NULL,
    notes TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_music_event FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE,
    CONSTRAINT fk_music_guest FOREIGN KEY (guest_id) REFERENCES guests(id) ON DELETE CASCADE,
    INDEX idx_music_event_guest (event_id, guest_id),
    INDEX idx_music_created (created_at)
);

-- Remove legacy plaintext invite codes if they were added previously.
ALTER TABLE guests DROP COLUMN IF EXISTS invite_code_plain;
