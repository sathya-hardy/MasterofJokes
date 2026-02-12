-- Reset tables in dependency order (child tables first)
DROP TABLE IF EXISTS jokesViewed;
DROP TABLE IF EXISTS jokes;
DROP TABLE IF EXISTS user;

-- Users: each has a unique nickname, an email, hashed password, joke credit balance, and role
CREATE TABLE user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nickname TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    password TEXT NOT NULL,
    jokebalance INTEGER NOT NULL DEFAULT 0,
    userRole INTEGER NOT NULL DEFAULT 0   -- 0 = regular user, 1 = moderator
);

-- Jokes: authored by a user, with aggregate rating data
CREATE TABLE jokes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id INTEGER NOT NULL,
    created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    ratings INTEGER NOT NULL DEFAULT 0,
    numberOfRatings INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (author_id) REFERENCES user (id)
);

-- Tracks which users have viewed (and optionally rated) each joke
CREATE TABLE jokesViewed (
    user_id INTEGER NOT NULL,
    joke_id INTEGER NOT NULL,
    has_rated INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES user (id),
    FOREIGN KEY (joke_id) REFERENCES jokes (id)
);

-- Auto-increment the author's joke balance when they post a new joke,
-- and record it as "viewed" by the author (so they can't rate their own joke)
CREATE TRIGGER incrementJokeBalance
AFTER INSERT ON jokes
FOR EACH ROW
BEGIN
    UPDATE user
    SET jokebalance = jokebalance + 1
    WHERE id = NEW.author_id;

    INSERT INTO jokesViewed(user_id, joke_id, has_rated)
    VALUES (NEW.author_id, NEW.id, 1);
END;

-- Seed a default moderator account (password: ilovemoderation)
INSERT INTO user(nickname, email, password, jokebalance, userRole)
VALUES (
    "moderator1",
    "mod@gmail.com",
    "scrypt:32768:8:1$QeU1DgYDo9soVzae$8a1d508b29ad55b495e34b8711988838cfc38ef2d8b4fa18211e0cc020143ee115ac8f98d393a0fee1fa5db56ad21b32bf126d3b8de59bcd56da6c0d499ee8c5",
    0,
    1
);
