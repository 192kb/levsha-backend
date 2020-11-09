const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const multer = require('multer');
const upload = multer({ dest: '/tmp/' });
const fs = require('fs');
const mysql = require('mysql');
const { v4: uuidv4 } = require('uuid');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const sqlString = require('sqlstring');
const SMSru = require('sms_ru');

const { credentials } = require('./credentials/db');
const { sessionSecret, passwordHashFunction } = require('./credentials/salt');
const { api } = require('./credentials/api');
const {
  basePath,
  serverPort,
  allowedOrigins,
  cookieMaxAge,
  serverApi,
  uploadsRelativePath,
  uploadsPath,
} = require('./configuration');
const { time } = require('console');

const CODE_SENDING_TIMEOUT_SECONDS = 30;

const connection = mysql.createConnection(credentials);
connection.connect(function (err) {
  if (err) {
    console.warn(err.stack);
    console.warn('Check your /credentials/db.js');
    return;
  }

  console.info('MySQL connected as id ' + connection.threadId);
});

// static
app.use(express.static('/upload'));

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
  res.header('Access-Control-Allow-Methods', 'PUT, POST, GET, DELETE, OPTIONS');
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

      console.log(phone, passwordHash, sql);

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

    return res.send({ uuid: query.uuid });
  });
});

const checkAuthentication = (req, res, next) => {
  // console.log(req.session.passport);
  console.log(req.session.id);
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

    if (!result.length)
      return res.status(404).send({
        code: 404,
        type: 'TASKS_NOT_FOUND',
        message: 'Работы не найдены',
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

app.put(basePath + '/task', (req, res) => {
  const query = {
    uuid: uuidv4(),
    title: req.body.title,
    description: req.body.description,
    price: req.body.price,
    category_id: req.body.category?.id,
    location_id: req.body.district?.id,
    user_id: req.session.passport?.user,
  };
  const sql = sqlString.format('insert into task set ?', query);
  connection.query(sql, (err, result) => {
    if (err) {
      return res.status(400).send({
        code: err.errno,
        type: err.code,
        message: err.sqlMessage,
      });
    }
    const imageIds = req.body.images?.map((image) => image.uuid);
    const imagesSql = sqlString.format(
      'update task_image set task_id = ? where uuid in (?)',
      [query.uuid, imageIds]
    );
    connection.query(imagesSql, (imagesErr) => {
      if (imagesErr) {
        return res.status(400).send({
          code: imagesErr.errno,
          type: imagesErr.code,
          message: imagesErr.sqlMessage,
        });
      }

      return res.send({
        uuid: query.uuid,
      });
    });
  });
});

app.post(
  basePath + '/task/image',
  checkAuthentication,
  upload.single('taskImage'),
  (req, res) => {
    var fileName = uuidv4() + '.jpg';
    fs.rename(
      req.file.path,
      uploadsPath + uploadsRelativePath + fileName,
      (err) => {
        if (err) {
          res.status(500).send(err);
        } else {
          const query = {
            uuid: uuidv4(),
            task_id: null,
            url: uploadsRelativePath + fileName,
            user_id: session.passport?.user,
          };
          const sql = sqlString.format('insert into task_image set ?', query);
          connection.query(sql, (err, result) => {
            if (err) {
              return res.status(400).send({
                code: err.errno,
                type: err.code,
                message: err.sqlMessage,
              });
            }

            return res.json(query);
          });
        }
      }
    );
  }
);

app.get(basePath + '/task/item/:task_id', (req, res) => {
  const sql = sqlString.format(
    'select * from task where uuid = ? limit 1',
    req.params.task_id
  );
  connection.query(sql, (err, result) => {
    if (err) {
      return res.status(400).send({
        code: err.errno,
        type: err.code,
        message: err.sqlMessage,
      });
    }
    if (result[0]) {
      const task = result[0];

      const userPromise = new Promise((resolve, reject) => {
        const sql = sqlString.format(
          'select uuid, photo_url, phone, firstname, lastname, secondname, city_id from user where uuid = ? limit 1',
          task.user_id
        );

        connection.query(sql, (err, result) => {
          if (err) reject(err);
          if (result) task.user = result[0];
          resolve(result);
        });
      });

      const imagePromise = new Promise((resolve, reject) => {
        const sql = sqlString.format(
          'select * from task_image where task_id = ? and is_deleted = 0 limit 3',
          task.uuid
        );

        connection.query(sql, (err, result) => {
          if (err) reject(err);
          if (result) task.images = result;
          resolve(result);
        });
      });

      const categoryPromise = new Promise((resolve, reject) => {
        const sql = sqlString.format(
          'select * from task_category where id = ? limit 1',
          task.category_id
        );

        connection.query(sql, (err, result) => {
          if (err) reject(err);
          if (result) task.category = result[0];
          resolve(result);
        });
      });

      const locationPromise = new Promise((resolve, reject) => {
        const sql = sqlString.format(
          'select * from location_district where id = ? limit 1',
          task.location_id
        );

        connection.query(sql, (err, result) => {
          if (err) reject(err);
          if (result) task.district = result[0];
          resolve(result);
        });
      });

      Promise.all([locationPromise, userPromise, categoryPromise, imagePromise])
        .then(() => res.send(task))
        .catch((err) => {
          res.status(400).send({
            code: err.errno,
            type: err.code,
            message: err.sqlMessage,
          });
        });
    } else {
      res.send(404);
    }
  });
});

app.post(
  basePath + '/task/item/:task_id',
  checkAuthentication,
  (req, res) => {}
);

app.delete(
  basePath + '/task/item/:task_id',
  checkAuthentication,
  (req, res) => {}
);

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

app.post(basePath + '/user/:user_id/generate-code', (req, res) => {
  const user_id = req.params.user_id;

  const userSql = sqlString.format(
    'select * from user where uuid = ? limit 1',
    user_id
  );
  connection.query(userSql, (err, users) => {
    if (err)
      return res.status(404).send({
        code: err.errno,
        type: err.code,
        message: err.sqlMessage,
      });

    const user = users[0];
    const sms = new SMSru(api.sms_api_key);

    if (user.is_deleted) {
      sms.stoplist_add(
        {
          phone: user.phone,
          text: 'Пользователь удален',
        },
        () => {
          return res.status(404).send({
            code: 300,
            type: 'USER_BANNED',
            message: 'Пользователь удален',
          });
        }
      );
    }

    if (user.phone_confirmed) {
      return res.status(404).send({
        code: 301,
        type: 'USER_CONFIRMED',
        message: 'Номер уже подтвержден для этого пользователя',
      });
    }

    const timeCheckSql = sqlString.format(
      'select * from user_code where user_id = ? and (DATEDIFF(second, date_created, GETDATE()) < ?)',
      [user_id, CODE_SENDING_TIMEOUT_SECONDS]
    );

    connection.query(timeCheckSql, (err, result) => {
      if (err)
        return res.status(400).send({
          code: err.errno,
          type: err.code,
          message: err.sqlMessage,
        });

      if (result[0]) {
        return res.status(423).send({
          code: 423,
          type: 'ALREADY_SENT',
          message: 'Код уже отправлен, повторная отправка запрещена',
        });
      }

      const code = generateSmsCode();

      const sql = sqlString.format('insert into user_code set ?', {
        user_id,
        code,
      });

      connection.query(sql, (err, result) => {
        if (err)
          return res.status(400).send({
            code: err.errno,
            type: err.code,
            message: err.sqlMessage,
          });

        sms.sms_send(
          {
            to: user.phone,
            text: 'Код: ' + code,
            from: 'Имя отправителя',
            translit: false,
            test: true,
          },
          (status) => {
            console.info('SMS code was sent for', user.phone, code, status);
            return res.status(200).send({ user_id, code, status });
          }
        );
      });
    });
  });
});

app.post(basePath + '/user/:user_id/confirm', (req, res) => {
  const user_id = req.params.user_id;
  const code = req.body.code;

  const userSql = sqlString.format(
    'select * from user where uuid = ? limit 1',
    user_id
  );
  connection.query(userSql, (err, users) => {
    if (err)
      return res.status(404).send({
        code: err.errno,
        type: err.code,
        message: err.sqlMessage,
      });

    const user = users[0];
    const sms = new SMSru(api.sms_api_key);

    if (user.is_deleted) {
      sms.stoplist_add(
        {
          phone: user.phone,
          text: 'Пользователь удален',
        },
        () => {
          return res.status(404).send({
            code: 300,
            type: 'USER_BANNED',
            message: 'Пользователь удален',
          });
        }
      );
    }

    if (user.phone_confirmed) {
      return res.status(200).send({
        code: 100,
        type: 'USER_CONFIRMED',
        message: 'Номер уже подтвержден для этого пользователя',
      });
    }

    const sql = sqlString.format(
      'select from user_code where user_id = ? and code = ?',
      [user_id, code]
    );

    connection.query(sql, (err, result) => {
      if (err)
        return res.status(400).send({
          code: err.errno,
          type: err.code,
          message: err.sqlMessage,
        });

      if (result[0]) {
        res.status(200).send({
          code: 100,
          type: 'SUCCESS',
          message: 'Пользователь подтверджен',
        });

        const removeCodesSql = sqlString.format(
          'delete from user_code where user_id = ?',
          user_id
        );
        connection.query(removeCodesSql, (err, result) => {
          if (err) {
            console.warn(err.sqlMessage, removeCodesSql);
          }
        });
      }
    });
  });
});

const generateSmsCode = () => Math.floor(1000 + Math.random() * 9000);

const cleanupPhone = (phoneRaw) => phoneRaw.replace(/[-+()\s]/g, '');

/// APPLICATION AVALIBILITY

app.listen(serverPort, () => {
  console.info('Listening on localhost: ' + serverPort);
  console.info('A api now available at ' + serverApi);
});
