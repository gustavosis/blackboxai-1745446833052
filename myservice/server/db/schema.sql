-- Update users table to include OAuth fields
ALTER TABLE users ADD COLUMN googleId TEXT;
ALTER TABLE users ADD COLUMN facebookId TEXT;
ALTER TABLE users ADD COLUMN username TEXT;
