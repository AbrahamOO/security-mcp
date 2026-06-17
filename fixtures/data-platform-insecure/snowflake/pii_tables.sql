-- INSECURE FIXTURE — PII columns defined with no masking/row-access policy.

CREATE TABLE customers (
  id            NUMBER,
  ssn           VARCHAR(11),
  credit_card   VARCHAR(19),
  email         VARCHAR(255),
  date_of_birth VARCHAR(10),
  phone_number  VARCHAR(20)
);
