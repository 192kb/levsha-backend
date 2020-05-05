const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const mysql = require('mysql');
const { v4: uuidv4 } = require('uuid');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const sqlString = require('sqlstring');

const { credetials } = require('./credentials/db');
const { sessionSecret, passwordHashFunction } = require('./credentials/salt');
const {
  basePath,
  serverPort,
  allowedOrigins,
  cookieMaxAge,
  serverApi,
  productionHomeURL,
} = require('./configuration');

const connection = mysql.createConnection({
  host: credetials.host,
  user: credetials.user,
  password: credetials.password,
  database: credetials.database,
});
connection.connect();

// parse application/json
app.use(bodyParser.json());

// parse application/x-www-form-urlencoded
app.use(
  bodyParser.urlencoded({
    extended: false,
  })
);

/// SESSION

app.use(
  session({
    genid: () => {
      return uuidv4(); // use UUIDs for session IDs
    },
    store: new FileStore(),
    secret: sessionSecret,
    resave: false,
    secure: true,
    saveUninitialized: true,
  })
);

/// CORS

app.use(function (req, res, next) {
  if (!allowedOrigins.includes(req.headers.origin)) {
    next();
    return;
  }
  res.header('Access-Control-Allow-Origin', req.headers.origin);
  res.header(
    'Access-Control-Allow-Headers',
    'Origin, X-Requested-With, Content-Type, Accept'
  );
  res.header('Access-Control-Allow-Credentials', true);
  next();
});

/// AUTH

app.use(passport.initialize());
app.use(
  passport.session({
    cookie: {
      maxAge: cookieMaxAge,
    },
  })
);

passport.use(
  new LocalStrategy(
    {
      usernameField: 'phone',
      passwordField: 'password',
      session: true,
    },
    (phone, password, done) => {
      const passwordHash = passwordHashFunction(password);
      const sql = sqlString.format(
        'select id, city_id from user where phone = ? and password_hash = ? and is_deleted = 0 limit 1',
        [phone, passwordHash]
      );
      connection.query(sql, function (err, users) {
        if (err) return done(err);
        if (!users[0]) {
          return done(null, false);
        }

        return done(null, users[0]);
      });
    }
  )
);

// tell passport how to serialize the user
passport.serializeUser((user, done) => {
  done(null, user.uuid);
});

passport.deserializeUser(function (userID, done) {
  const sql = sqlString.format(
    'select * from user where uuid = ? limit 1',
    userID
  );
  connection.query(sql, function (err, users) {
    if (err) return done(err);
    done(null, users[0]);
  });
});

app.post(basePath + '/user/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) console.log(err);
    if (info) console.log(info);

    req.login(user, (err) => {
      if (err || !user)
        return res.send({
          success: false,
          error: info,
        });

      return res.send({
        success: true,
        user: user,
      });
    });
  })(req, res, next);
});

app.get(basePath + '/user/logout', function (req, res) {
  req.logout();
  res.send({
    status: 'logged-out',
  });
});

app.post(basePath + '/user', (req, res, next) => {
  var query = {
    uuid: uuidv4(),
    firstname: req.body.firstname,
    secondname: req.body.secondname,
    lastname: req.body.lastname,
    phone: req.body.phone,
    password_hash: passwordHashFunction(req.body.password),
    city_id: req.body.city_id,
  };
  var sql = sqlString.format('insert into user set ?', query);
  connection.query(sql, function (err, result) {
    if (err)
      return res.status(400).send({
        code: err.errno,
        type: err.code,
        message: err.sqlMessage,
      });

    return res.send(result);
  });
});

/// ROUTING

app.get(basePath + '/ping', function (req, res) {
  return res.send('pong');
});

app.get(basePath + '/city', function (req, res) {
  connection.query(
    'select * from location_city where is_deleted = 0',
    function (err, result) {
      if (err)
        return res.status(400).send({
          code: err.errno,
          type: err.code,
          message: err.sqlMessage,
        });

      return res.send(result);
    }
  );
});

app.get(basePath + '/city/:city_id/locations', function (req, res) {
  const sql = sqlString.format(
    'select * from location where city_id = ?',
    req.params.city_id
  );
  connection.query(sql, function (err, result) {
    if (err) return res.send(err);

    return res.send(result);
  });
});

app.get(basePath + '/category', function (req, res) {
  connection.query('select * from category order by sorting', function (
    err,
    result
  ) {
    if (err) return res.send(err);

    return res.send(result);
  });
});

app.get(basePath + '/user', checkAuthentication, function (req, res) {
  const sql = sqlString.format(
    'select uuid, photo_link, phone, firstname, lastname, secondname, vk_profile, ok_profile, fb_profile, ig_profile, tw_profile, yt_profile, be_profile, li_profile, hh_profile, phone_confirmed, email, email_confirmed, city_id from user where uuid = ? LIMIT 1',
    req.session.passport.user
  );

  connection.query(sql, function (err, result) {
    if (err) return res.status(400).send(err);

    let user = result[0];

    const city_sql = sqlString.format(
      'select * from location_city where is_deleted = 0 and id = ?',
      user.city_id
    );

    connection.query(city_sql, function (err, result) {
      if (err) return res.status(400).send(err);

      user.city = result[0];
      return res.send(user);
    });
  });
});

function checkAuthentication(req, res, next) {
  if (req.isAuthenticated()) {
    next();
  } else {
    res.status(401).send({
      status: 'no-auth',
    });
  }
}

/// APPLICATION AVALIBILITY

app.listen(serverPort, () => {
  console.log('Listening on localhost: ' + serverPort);
  console.log('A api now available at ' + serverApi);
});
