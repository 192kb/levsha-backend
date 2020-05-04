var baseDomainName = '192kb.ru';
var basePath = '/levsha-pass'

module.exports = {
    baseDomainName,
    basePath,
    serverPort: 3001,
    productionPort: 3001,
    serverApi: 'https://' + baseDomainName + basePath,
    productionHomeURL: 'https://' + baseDomainName + basePath,
    minPassword_length: 4,
    allowedOrigins: [
        'http://localhost:3000', 'https://dev.' + baseDomainName,
        'https://' + baseDomainName
    ],
    cookieMaxAge: 3600000,
    brand: 'Levsha'
}