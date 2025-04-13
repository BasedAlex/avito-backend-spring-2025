-- +goose Up
-- +goose StatementBegin
CREATE TYPE reception_status AS ENUM ('in_progress', 'close');

CREATE TYPE product_type AS ENUM ('electronics', 'clothing', 'shoes');

CREATE TYPE user_role AS ENUM ('moderator', 'employee');

CREATE TYPE pvz_city AS ENUM ('Moscow', 'Saint-Petersburg', 'Kazan');

CREATE TABLE pvz (
    id UUID PRIMARY KEY,
    registration_date TIMESTAMP NOT NULL,
    city pvz_city NOT NULL,
    last_reception_id UUID 
);

CREATE TABLE receptions (
    id UUID PRIMARY KEY, 
    received_at TIMESTAMP NOT NULL,
    pvz_id UUID NOT NULL REFERENCES pvz(id) ON DELETE CASCADE,
    status reception_status DEFAULT 'in_progress'
);

CREATE TABLE products (
    id UUID PRIMARY KEY,
    received_at TIMESTAMP NOT NULL,
    type product_type NOT NULL,
    reception_id UUID NOT NULL REFERENCES receptions(id) ON DELETE CASCADE
);

CREATE TABLE users (
    id UUID PRIMARY KEY,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(100) NOT NULL,
    role user_role NOT NULL
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE pvz;
DROP TABLE receptions;
DROP TABLE products;
DROP TABLE users;
-- +goose StatementEnd
