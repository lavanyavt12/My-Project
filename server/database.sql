CREATE DATABASE secure_transfer;
USE secure_transfer;
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255),
    password VARCHAR(255)
);
INSERT INTO users (username, password) VALUES ('lavanya', 'pass123');