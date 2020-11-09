import bcrypt from 'bcrypt';
const saltRounds = 10;

export const hashPassword = (
  password: string,
  callback: (hash: string) => void
) => bcrypt.hash(password, saltRounds).then((hash) => callback(hash));

export const comparePasswordWithHash = (
  password: string,
  hash: string,
  callback: (result: boolean) => void
) => bcrypt.compare(password, hash).then((result) => callback(result));
