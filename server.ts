import express, { Request, Response } from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import fs from 'fs';
import mysql from 'mysql';
import { v4 as uuidv4 } from 'uuid';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import sqlString from 'sqlstring';
import { District, Task, TaskCategory, TaskImage, User } from './model';
import { credentials } from './credentials/db';
import {
  allowedOrigins,
  basePath,
  uploadsPath,
  uploadsRelativePath,
  serverPort,
  serverApi,
} from './configuration';
import { comparePasswordWithHash, hashPassword } from './cryptography';
import session from 'express-session';
import { sessionSecret } from './credentials/salt';

const app = express();
const upload = multer({ dest: '/tmp/' });

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

app.use(cookieParser());
app.use(
  session({
    secret: sessionSecret,
    resave: true,
    saveUninitialized: false,
    cookie: {
      httpOnly: false,
      sameSite: 'none',
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());

/// CORS

app.use((req, res, next) => {
  if (req.headers.origin && !allowedOrigins.includes(req.headers.origin)) {
    next();
    return;
  }
  res.header('Access-Control-Allow-Origin', req.headers.origin);
  res.header(
    'Access-Control-Allow-Headers',
    'Origin, X-Requested-With, Content-Type, Accept'
  );
  res.header('Access-Control-Allow-Methods', 'PUT, POST, GET, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});

/// AUTH

passport.use(
  new LocalStrategy(
    {
      usernameField: 'phone',
      passwordField: 'password',
    },
    (
      phone: string,
      password: string,
      done: (
        error: mysql.MysqlError | {} | null,
        arg1?: boolean | undefined
      ) => void
    ) => {
      const sql = sqlString.format(
        'select uuid, photo_url, phone, firstname, lastname, secondname, vk_profile, ig_profile, tw_profile, li_profile, hh_profile, phone_confirmed, email, email_confirmed, city_id, password_hash from user where phone = ? and is_deleted = 0 limit 1',
        [phone]
      );

      connection.query(sql, (err, users) => {
        if (err) return done(err);
        if (!users[0]) {
          return done(
            {
              code: 401,
              type: 'AUTH_NOT_PASSED',
              message: 'Неправильный логин',
            },
            false
          );
        }

        const user = users[0];

        comparePasswordWithHash(password, user.password_hash, (valid) => {
          if (valid) {
            const city_sql = sqlString.format(
              'select * from location_city where is_deleted = 0 and id = ?',
              user.city_id
            );

            connection.query(city_sql, (err, result) => {
              if (err) return done(err);

              user.city = result[0];
              user.password_hash = undefined;
              return done(null, user);
            });
          } else {
            return done(
              {
                code: 401,
                type: 'AUTH_NOT_PASSED',
                message: 'Неправильный пароль',
              },
              false
            );
          }
        });
      });
    }
  )
);

// tell passport how to serialize the user
passport.serializeUser((user: User, done) => {
  done(null, user.uuid);
});

passport.deserializeUser((uuid: string, done) => {
  const sql = sqlString.format('select * from user where uuid = ? limit 1', [
    uuid,
  ]);
  connection.query(sql, (err, users) => {
    if (err) return done(err);
    done(null, users[0]);
  });
});

app.post(basePath + '/user/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    req.login(user, (err) => {
      if (err || !user) return res.status(401).send(err);
      return res.send(user);
    });
  })(req, res, next);
});

app.get(basePath + '/user/logout', (req, res) => {
  req.logout();
  req.session?.destroy(function (err) {
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
  hashPassword(req.body.password, (hash) => {
    var query = {
      uuid: uuidv4(),
      firstname: req.body.firstname,
      secondname: req.body.secondname,
      lastname: req.body.lastname,
      phone: req.body.phone,
      password_hash: hash,
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
});

const checkAuthentication = (req: Request, res: Response, next: () => void) => {
  if ((req.session as any)?.passport?.user) {
    next();
  } else {
    res.status(401).send({
      req,
      code: 401,
      message: 'Вы не авторизованы',
      type: 'NO_AUTH',
    });
  }
};

app.get(basePath + '/user', checkAuthentication, (req, res) => {
  const sql = sqlString.format(
    'select uuid, photo_url, phone, firstname, lastname, secondname, vk_profile, ig_profile, tw_profile, li_profile, hh_profile, phone_confirmed, email, email_confirmed, city_id from user where uuid = ? LIMIT 1',
    (req.session as any)?.passport.user
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
    [req.params.city_id]
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

const getTaskByQuery = (res: Response, sql: string) =>
  connection.query(sql, (err, result: Task[]) => {
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
      ...new Set(
        result.map(
          (task) => (task as unknown as { category_id: number }).category_id
        )
      ),
    ];
    const userIds = [
      ...new Set(
        result.map((task) => (task as unknown as { user_id: string }).user_id)
      ),
    ];
    const districtIds = [
      ...new Set(
        result.map(
          (task) => (task as unknown as { location_id: number }).location_id
        )
      ),
    ];

    let taskCategories: TaskCategory[] = [];
    let users: User[] = [];
    let districts: District[] = [];
    let images: {
      [x: string]: TaskImage;
    } = {};

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
            [task.uuid]
          );

          connection.query(sql, (err, result: TaskImage) => {
            if (err) reject(err);

            images[task.uuid || 'undefined'] = result;
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
              user: users.find(
                (user) =>
                  user.uuid === (task as unknown as { user_id: string }).user_id
              ),
              district: districts.find(
                (district) =>
                  district.id ===
                  (task as unknown as { location_id: number }).location_id
              ),
              category: taskCategories.find(
                (category) =>
                  category.id ===
                  (task as unknown as { category_id: number }).category_id
              ),
              images: images[task.uuid || 'undefined'],
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

app.get(basePath + '/task', (req, res) => {
  const sql =
    'select * from task WHERE date_created > DATE_ADD(CURDATE(), INTERVAL -3 DAY) and is_deleted = 0'; // last 3 days to be displayed

  return getTaskByQuery(res, sql);
});

app.get(basePath + '/user/task', checkAuthentication, (req, res) => {
  const userId = (req.session as any)?.passport?.user;

  const sql = sqlString.format('select * from task where user_id = ?', [
    userId,
  ]);

  return getTaskByQuery(res, sql);
});

app.put(basePath + '/task', (req, res) => {
  const query = {
    uuid: uuidv4(),
    title: req.body.title,
    description: req.body.description,
    price: req.body.price,
    category_id: req.body.category?.id,
    location_id: req.body.district?.id,
    user_id: (req.session as any)?.passport?.user,
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
    const imageIds: string[] = req.body.images?.map(
      (image: TaskImage) => image.uuid
    );
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
            user_id: (req.session as any)?.passport?.user,
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
    'select * from task where uuid = ? and is_deleted = 0',
    [req.params.task_id]
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
          [task.user_id]
        );

        connection.query(sql, (err, result) => {
          if (err) return reject({ ...err, sql });
          if (result) task.user = result[0];
          resolve(result);
        });
      });

      const imagePromise = new Promise((resolve, reject) => {
        const sql = sqlString.format(
          'select * from task_image where task_id = ? and is_deleted = 0 limit 3',
          [task.uuid]
        );

        connection.query(sql, (err, result) => {
          if (err) return reject({ ...err, sql });
          if (result) task.images = result;
          resolve(result);
        });
      });

      const categoryPromise = new Promise((resolve, reject) => {
        const sql = sqlString.format(
          'select * from task_category where id = ? limit 1',
          [task.category_id]
        );

        connection.query(sql, (err, result) => {
          if (err) return reject({ ...err, sql });
          if (result) task.category = result[0];
          resolve(result);
        });
      });

      const locationPromise = new Promise((resolve, reject) => {
        const sql = sqlString.format(
          'select * from location_district where id = ? limit 1',
          [task.location_id]
        );

        connection.query(sql, (err, result) => {
          if (err) return reject({ ...err, sql });
          if (result) task.district = result[0];
          resolve(result);
        });
      });

      Promise.all([locationPromise, userPromise, categoryPromise, imagePromise])
        .then(() => res.send(task))
        .catch((err) => {
          res.status(400).send({
            sql: err.sql,
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

app.post(basePath + '/task/item/:task_id', checkAuthentication, (req, res) => {
  const query = {
    title: req.body.title,
    description: req.body.description,
    price: req.body.price,
    category_id: req.body.category?.id,
    location_id: req.body.district?.id,
  };
  const taskId = req.params.task_id;
  const userId = (req.session as any)?.passport?.user;

  const taskSql = sqlString.format(
    'update task set ? where uuid = ? and user_id = ?',
    [query, taskId, userId]
  );

  connection.query(taskSql, (err, result) => {
    if (err) {
      return res.status(400).send({
        code: err.errno,
        type: err.code,
        message: err.sqlMessage,
      });
    }

    const oldImagesSql = sqlString.format(
      'update task_image set task_id = NULL where task_id = ?',
      [taskId]
    );

    connection.query(oldImagesSql, (err, result) => {
      if (err) {
        return res.status(400).send({
          code: err.errno,
          type: err.code,
          message: err.sqlMessage,
        });
      }

      const imageIds = req.body.images?.map((image: TaskImage) => image.uuid);
      if (imageIds.length) {
        const imagesSql = sqlString.format(
          'update task_image set task_id = ? where uuid in (?)',
          [taskId, imageIds]
        );

        connection.query(imagesSql, (imagesErr) => {
          if (imagesErr) {
            return res.status(400).send({
              code: imagesErr.errno,
              type: imagesErr.code,
              message: imagesErr.sqlMessage,
              imageIds,
              imagesSql,
            });
          }

          return res.send({
            uuid: taskId,
          });
        });
      } else {
        return res.send({
          uuid: taskId,
        });
      }
    });
  });
});

app.delete(
  basePath + '/task/item/:task_id',
  checkAuthentication,
  (req, res) => {
    const taskId = req.params.task_id;
    const userId = (req.session as any)?.passport?.user;

    const taskQuery = sqlString.format(
      'update task set is_deleted = 1 where uuid = ? and user_id = ?',
      [taskId, userId]
    );

    connection.query(taskQuery, (err, result) => {
      if (err) {
        return res.status(400).send({
          code: err.errno,
          type: err.code,
          message: err.sqlMessage,
        });
      }

      return res.send({
        uuid: taskId,
      });
    });
  }
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

/// APPLICATION AVAILABILITY

app.listen(serverPort, () => {
  console.info(`Listening api:port ${serverApi}:${serverPort}`);
});
