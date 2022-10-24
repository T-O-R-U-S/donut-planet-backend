create table users(
    id SERIAL PRIMARY KEY,
    username VARCHAR(16) NOT NULL UNIQUE,
    profile_picture VARCHAR(255),
    bio VARCHAR(255) NULL,
    email VARCHAR(255) CHARACTER SET utf8 COLLATE utf8_unicode_520_ci NOT NULL UNIQUE,
    password_hash CHAR(60) NOT NULL,
    auth_token VARCHAR(255) NOT NULL,
    # Is the account email verified?
    verified BOOLEAN DEFAULT FALSE,
    # Check if email is valid.
    CHECK ( email REGEXP '^[a-zA-Z0-9][a-zA-Z0-9.!#$%&\'*+-/=?^_`{|}~]*?[a-zA-Z0-9._-]?@[a-zA-Z0-9][a-zA-Z0-9._-]*?[a-zA-Z0-9]?\\.[a-zA-Z]{2,63}$')
);

create table posts(
    id SERIAL PRIMARY KEY,
    author BIGINT UNSIGNED,
    title VARCHAR(255),
    content TEXT,
    creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (author) REFERENCES users(id) ON DELETE SET NULL
);

create table comments(
    id SERIAL PRIMARY KEY,
    user_id BIGINT UNSIGNED,
    post_id BIGINT UNSIGNED NOT NULL,
    content TEXT,
    creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) references users(id) ON DELETE SET NULL,
    FOREIGN KEY (post_id) references posts(id) ON DELETE CASCADE
);

create table likes(
    # Vitess will not let me create this table without having a column with a primary key.
    id SERIAL PRIMARY KEY,
    post_id BIGINT UNSIGNED NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

create index user_index on users(id, username, email, auth_token);

create index post_index on posts(id, title, content(500));

create index like_index on likes(post_id);

create index comment_index on comments(user_id, post_id);