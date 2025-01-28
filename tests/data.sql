INSERT INTO user (nickname, email, password, userRole)
VALUES
  ('test', 'test@edu.com', 'pbkdf2:sha256:50000$TCI4GzcX$0de171a4f4dac32e3364c7ddc7c14f3e2fa61f2d17574483f7ffbb431b4acb2f', 0),
  ('other', 'test@comcast.com', 'pbkdf2:sha256:50000$kJPKsz6N$d2d4784f1b030a9761f5ccaeeaca413f27f2ecb76d6168407af962ddce849f79', 0);

INSERT INTO jokes (title, body, author_id, created, ratings, numberOfRatings)
VALUES
  ('test title', 'test' || x'0a' || 'body', 1, '2018-01-01 00:00:00', 0, 0);