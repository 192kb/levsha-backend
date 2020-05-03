var baseDomainName = '192kb.ru';

module.exports = {
    baseDomainName,
    clientPort: 3000,
    serverPort: 3001,
    productionPort: 3002,
    serverApi: 'https://' + baseDomainName,
    productionHomeURL: 'https://' + baseDomainName,
    minPassword_length: 4,
    allowedOrigins: [
        'http://localhost:3000', 'https://dev.' + baseDomainName,
        'https://' + baseDomainName
    ],
    cookieMaxAge: 3600000,
    brand: 'Levsha'
}
