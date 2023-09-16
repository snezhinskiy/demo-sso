INSERT INTO app_user (id, username, password, active, created_at)
    VALUES ('7f000001-8a56-11d1-818a-56e25ae30000', 'admin', '{noop}secret', true, NOW());
INSERT INTO app_user (id, username, password, active, created_at)
    VALUES ('7f000001-8a56-1695-818a-56687e770000', 'user', '{noop}secret', true, NOW());

INSERT INTO role (id, name) VALUES (1, 'ADMIN');
INSERT INTO role (id, name) VALUES (2, 'USER');

INSERT INTO user_role (user_id, role_id) VALUES ('7f000001-8a56-11d1-818a-56e25ae30000', 1);
INSERT INTO user_role (user_id, role_id) VALUES ('7f000001-8a56-1695-818a-56687e770000', 2);

INSERT INTO authority (id, name) VALUES (1, 'ARTICLE_READ');
INSERT INTO authority (id, name) VALUES (2, 'ARTICLE_WRITE');

-- ADMIN can read and write
INSERT INTO role_authority (role_id, authority_id) VALUES (1, 1);
INSERT INTO role_authority (role_id, authority_id) VALUES (1, 2);

-- USER only can read
INSERT INTO role_authority (role_id, authority_id) VALUES (2, 1);
