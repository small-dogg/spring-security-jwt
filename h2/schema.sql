CREATE TABLE user(
    id int,
    username varchar,
    password varchar(20),
    age int,
    address1 varchar(30),
    address2 varchar(30),
    expired boolean,
    locked,
    enabled boolean
)