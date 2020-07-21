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

const { credentials } = require('./credentials/db');
const { sessionSecret, passwordHashFunction } = require('./credentials/salt');
const {
  basePath,
  serverPort,
  allowedOrigins,
  cookieMaxAge,
  serverApi,
} = require('./configuration');

const connection = mysql.createConnection(credentials);
connection.connect(function (err) {
  if (err) {
    console.warn(err.stack);
    console.warn('Check your /credentials/db.js');
    return;
  }

  console.info('MySQL connected as id ' + connection.threadId);
});

// parse application/json
app.use(bodyParser.json());

// parse application/x-www-form-urlencoded
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);

/// SESSION

app.use(passport.initialize());
app.use(passport.session());
app.use(
  session({
    store: new FileStore({
      ttl: cookieMaxAge,
      reapAsync: true,
      reapSyncFallback: true,
    }),
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: false,
      domain: '.192kb.ru',
      expires: new Date() + cookieMaxAge,
      maxAge: cookieMaxAge,
      secure: false,
      sameSite: 'none',
    },
  })
);

/// CORS

app.use((req, res, next) => {
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
        'select uuid, photo_url, phone, firstname, lastname, secondname, vk_profile, ok_profile, ig_profile, tw_profile, yt_profile, be_profile, li_profile, hh_profile, phone_confirmed, email, email_confirmed, city_id from user where phone = ? and password_hash = ? and is_deleted = 0 limit 1',
        [phone, passwordHash]
      );

      connection.query(sql, (err, users) => {
        if (err) return done(err);
        if (!users[0]) {
          return done(null, false);
        }

        const user = users[0];

        const city_sql = sqlString.format(
          'select * from location_city where is_deleted = 0 and id = ?',
          user.city_id
        );

        connection.query(city_sql, (err, result) => {
          if (err) return done(err);

          user.city = result[0];
          return done(null, user);
        });
      });
    }
  )
);

// tell passport how to serialize the user
passport.serializeUser((user, done) => {
  done(null, user.uuid);
});

passport.deserializeUser((uuid, done) => {
  const sql = sqlString.format(
    'select * from user where uuid = ? limit 1',
    uuid
  );
  connection.query(sql, (err, users) => {
    if (err) return done(err);
    done(null, users[0]);
  });
});

app.post(basePath + '/user/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    req.login(user, (err) => {
      if (err || !user)
        return res.status(401).send({
          code: 401,
          type: 'AUTH_NOT_PASSED',
          message: 'Неправильный логин / пароль',
        });

      return res.send(user);
    });
  })(req, res, next);
});

app.get(basePath + '/user/logout', (req, res) => {
  req.logout();
  req.session.destroy(function (err) {
    if (err) {
      console.warn(err);
    } else {
      res.clearCookie('connect.sid');
      res.send({
        status: 'logged-out',
      });
    }
  });
});

app.put(basePath + '/user', (req, res, next) => {
  var query = {
    uuid: uuidv4(),
    firstname: req.body.firstname,
    secondname: req.body.secondname,
    lastname: req.body.lastname,
    phone: req.body.phone,
    password_hash: passwordHashFunction(req.body.password),
    city_id: req.body.city.id,
  };
  var sql = sqlString.format('insert into user set ?', query);
  connection.query(sql, (err, result) => {
    if (err)
      return res.status(400).send({
        code: err.errno,
        type: err.code,
        message: err.sqlMessage,
      });

    return res.send(result);
  });
});

const checkAuthentication = (req, res, next) => {
  if (req.session && req.session.passport && req.session.passport.user) {
    next();
  } else {
    res.status(401).send({
      code: 401,
      message: 'Вы не авторизованы',
      type: 'NO_AUTH',
    });
  }
};

app.get(basePath + '/user', checkAuthentication, (req, res) => {
  const sql = sqlString.format(
    'select uuid, photo_url, phone, firstname, lastname, secondname, vk_profile, ok_profile, ig_profile, tw_profile, yt_profile, be_profile, li_profile, hh_profile, phone_confirmed, email, email_confirmed, city_id from user where uuid = ? LIMIT 1',
    req.session.passport.user
  );

  connection.query(sql, (err, result) => {
    if (err) return res.status(401).send(err);

    let user = result[0];

    const city_sql = sqlString.format(
      'select * from location_city where is_deleted = 0 and id = ?',
      user.city_id
    );

    connection.query(city_sql, (err, result) => {
      if (err) return res.status(400).send(err);

      user.city = result[0];
      return res.send(user);
    });
  });
});

/// ROUTING

app.get(basePath + '/ping', (req, res) => {
  return res.send('pong');
});

app.get(basePath + '/city', (req, res) => {
  connection.query(
    'select * from location_city where is_deleted = 0',
    (err, result) => {
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

app.get(basePath + '/city/:city_id/district', (req, res) => {
  const sql = sqlString.format(
    'select * from location_district where city_id = ?',
    req.params.city_id
  );
  connection.query(sql, (err, result) => {
    if (err)
      return res.status(400).send({
        code: err.errno,
        type: err.code,
        message: err.sqlMessage,
      });

    return res.send(result);
  });
});

app.get(basePath + '/task/', (req, res) => {
  const sql = sqlString.format('select * from task limit 10');
  connection.query(sql, (err, result) => {
    if (err)
      return res.status(400).send({
        code: err.errno,
        type: err.code,
        message: err.sqlMessage,
      });

    const taskCategoryIds = [
      ...new Set(result.map((task) => task.category_id)),
    ];
    const userIds = [...new Set(result.map((task) => task.user_id))];
    const districtIds = [...new Set(result.map((task) => task.location_id))];

    let taskCategories = [];
    let users = [];
    let districts = [];
    let images = {};

    const taskPromise = new Promise((resolve, reject) => {
      const sql = sqlString.format(
        'select * from task_category where id in (?)',
        [taskCategoryIds]
      );

      connection.query(sql, (err, result) => {
        if (err) reject(err);

        taskCategories = result;
        resolve(result);
      });
    });

    const userPromise = new Promise((resolve, reject) => {
      const sql = sqlString.format(
        'select uuid, photo_url, phone, firstname, lastname, secondname, city_id from user where uuid in (?)',
        [userIds]
      );

      connection.query(sql, (err, result) => {
        if (err) reject(err);

        users = result;
        resolve(result);
      });
    });

    const districtPromise = new Promise((resolve, reject) => {
      const sql = sqlString.format(
        'select * from location_district where id in (?)',
        [districtIds]
      );

      connection.query(sql, (err, result) => {
        if (err) reject(err);

        districts = result;
        resolve(result);
      });
    });

    const imagePromises = result.map(
      (task) =>
        new Promise((resolve, reject) => {
          const sql = sqlString.format(
            'select * from task_image where task_id = ? and is_deleted = 0',
            task.uuid
          );

          connection.query(sql, (err, result) => {
            if (err) reject(err);

            images[task.uuid] = result;
            resolve(result);
          });
        })
    );

    Promise.all([taskPromise, userPromise, districtPromise, ...imagePromises])
      .then(() => {
        res.send(
          result.map((task) => {
            return {
              ...task,
              user: users.find((user) => user.uuid === task.user_id),
              district: districts.find(
                (district) => district.id === task.location_id
              ),
              category: taskCategories.find(
                (category) => category.id === task.category_id
              ),
              images: images[task.uuid],
            };
          })
        );
      })
      .catch((err) => {
        res.status(400).send({
          code: err.errno,
          type: err.code,
          message: err.sqlMessage,
        });
      });
  });
});

app.put(basePath + '/task/', (req, res) => {});

app.get(basePath + '/task/item/:task_id', (req, res) => {});

app.post(basePath + '/task/item/:task_id', (req, res) => {});

app.delete(basePath + '/task/item/:task_id', (req, res) => {});

app.get(basePath + '/task/category', (req, res) => {
  connection.query(
    'select * from task_category order by sorting',
    (err, result) => {
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

app.put(basePath + '/task/category', (req, res) => {});

/// APPLICATION AVALIBILITY

app.listen(serverPort, () => {
  console.info('Listening on localhost: ' + serverPort);
  console.info('A api now available at ' + serverApi);
});
