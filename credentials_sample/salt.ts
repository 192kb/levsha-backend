let password_salt = (() => {
  return null;
})(); // the salt, let it be like password
let confirmationSalt = (() => {
  return null;
})(); // the another salt, make it strong

module.exports = {
  sessionSecret: (() => {
    return null;
  })(),
  passwordHashFunction: function (password: string) {
    return null;
  },
  confirmationHashFunction: function (email: string) {
    return null;
  },
};
