export const baseDomainName = '192kb.ru';
export const basePath = '/levsha-api';
export const serverPort = 3001;
export const productionPort = 3001;
export const serverApi = 'https://' + baseDomainName + basePath;
export const productionHomeURL = 'https://' + baseDomainName + basePath;
export const minPassword_length = 4;
export const allowedOrigins = [
  'http://localhost:3000',
  'https://dev.' + baseDomainName,
  'https://' + baseDomainName,
];
export const cookieMaxAge = 3600000;
export const brand = 'Levsha';
export const uploadsPath = __dirname + '/../html';
export const uploadsRelativePath = '/uploads/';
