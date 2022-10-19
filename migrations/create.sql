create table users(
                      id SERIAL PRIMARY KEY,
                      username VARCHAR(16) NOT NULL UNIQUE,
                      profile_picture VARCHAR(255),
                      bio VARCHAR(255) NULL,
                      email VARCHAR(255) CHARACTER SET utf8 COLLATE utf8_unicode_520_ci NOT NULL UNIQUE,
                      password_hash TEXT NOT NULL
);

create table posts(
                      id SERIAL PRIMARY KEY,
                      user BIGINT UNSIGNED NOT NULL,
                      title VARCHAR(255),
                      content TEXT,
                      FOREIGN KEY (user) REFERENCES users(id)
);

create table comments(
    id SERIAL PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    post_id BIGINT UNSIGNED NOT NULL,
    content TEXT,
    FOREIGN KEY (user_id) references users(id),
    FOREIGN KEY (post_id) references posts(id)
);

create table likes(
    # Vitess will not let me create this table without having a column with a primary key.
    id SERIAL PRIMARY KEY,
    post_id BIGINT UNSIGNED NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    FOREIGN KEY (post_id) REFERENCES posts(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

create index user_index on users(id, username, email);

create index post_index on posts(id, title, content(500));

create index like_index on likes(post_id);

create index comment_index on comments(user_id, post_id);