-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING *;

-- name: DeleteUsers :exec
DELETE FROM users;

-- name: GetUserByEmail :one 
SELECT * FROM users
WHERE users.email = $1;

-- name: GetUserById :one 
SELECT * FROM users 
WHERE users.id = $1;

-- name: UpdateUserEmailAndPassword :exec 
UPDATE users 
SET email = $1, hashed_password = $2, updated_at = NOW()
WHERE users.id = $3;

-- name: UpgradeUserToChirpyRed :exec 
UPDATE users 
SET is_chirpy_red = TRUE 
WHERE users.id = $1;