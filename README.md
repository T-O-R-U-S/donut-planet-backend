# Donut Planet (Backend)

Donut Planet is going to be a social media website where you can uh...
do things :)

# Setup

Since this project contains passwords that shouldn't be shared to the public,
there is a `secrets` folder that was created to store things that should not
be shared with the public. The directory structure is as follows:

```
secrets
L conn_url.secret
L private_key.secret
```

The code will reference these files for database interactions or
JWT authentication, so it's important that you create them.

`conn_url.secret` contains the database URL connection string

`private_key.secret` contains the private key used to sign JWTs.

These are imported as compile-time constants, so if they are missing,
the program will not compile.

## What is Donut Planet?

It's going to be a social media platform where the 'gimmick' is that you have to earn Sprinkles to progress.