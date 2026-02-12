DROP TABLE IF EXISTS jokesViewed;
DROP TABLE IF EXISTS jokes;
DROP TABLE IF EXISTS user;


CREATE TABLE user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nickname TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    password TEXT NOT NULL,
    jokebalance INTEGER,
    userRole INTEGER
);

CREATE TABLE jokes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id INTEGER NOT NULL,
    created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    ratings INTEGER,
    numberOfRatings INTEGER,
    FOREIGN KEY (author_id) REFERENCES user (id)
);

CREATE TABLE jokesViewed (
    user_id INTEGER NOT NULL,
    joke_id INTEGER NOT NULL,
    has_rated INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES user (id),
    FOREIGN KEY (joke_id) REFERENCES jokes (id)
);

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

INSERT INTO user(nickname, email, password, jokebalance, userRole) VALUES ("moderator1", "mod@gmail.com", "scrypt:32768:8:1$QeU1DgYDo9soVzae$8a1d508b29ad55b495e34b8711988838cfc38ef2d8b4fa18211e0cc020143ee115ac8f98d393a0fee1fa5db56ad21b32bf126d3b8de59bcd56da6c0d499ee8c5", 0, 1); 
--This moderator password is ilovemoderation