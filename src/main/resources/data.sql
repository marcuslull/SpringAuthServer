INSERT INTO users (username, password, enabled) VALUES
        ('user', '{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW', true),
        ('admin', '{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW', true);



INSERT INTO authorities (username, authority) VALUES
        ('user', 'USER'),
        ('admin', 'USER'),
        ('admin', 'ADMIN');