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
import { rateLimit } from 'express-rate-limit';
import path from 'path';
import lusca from 'lusca';

const app = express();
const uploadRoot = path.join(uploadsPath, uploadsRelativePath);
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      // Ensure uploads are stored under the configured uploads directory
      cb(null, uploadRoot);
    },
    filename: (req, file, cb) => {
      // Use a server-generated filename to avoid using any user-controlled path parts
      const generatedName = uuidv4() + '.jpg';
      cb(null, generatedName);
    },
  }),
});

// Apply CSRF protection for all routes that rely on cookie-based authentication.
// This should be registered after cookieParser/session setup (configured elsewhere
// in this file) and before any state-changing route handlers.
app.use(lusca.csrf());

const uploadImageRateLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 10, // limit each IP to 10 image upload requests per windowMs
});

const connection = mysql.createConnection(credentials);
connection.connect(function (err) {
  if (err) {
    console.warn(err.stack);
    console.warn('Check your /credentials/db.js');
    return;
  }

  console.info(`MySQL connected as id ${connection.threadId}`);
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
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());

/// CORS

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin);
  res.header(
    'Access-Control-Allow-Headers',
    'Origin, X-Requested-With, Content-Type, Accept'
  );
  res.header('Access-Control-Allow-Methods', 'PUT, POST, GET, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});

/// RATE LIMITER
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 250, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// Apply the rate limiting middleware to all requests
app.use(limiter);

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
passport.serializeUser(
  (user: unknown, done: (err: any, id?: unknown) => void) => {
    done(null, (user as User).uuid);
  }
);

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

app.get(basePath + '/user/logout', (req, res, next) => {
  req.logout(function (err1) {
    if (err1) {
      return next(err1);
    }

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
});

app.put(basePath + '/user', (req, res, next) => {
  hashPassword(req.body.password, (hash) => {
    const query = {
      uuid: uuidv4(),
      firstname: req.body.firstname,
      secondname: req.body.secondname,
      lastname: req.body.lastname,
      phone: req.body.phone,
      password_hash: hash,
      city_id: req.body.city.id,
    };
    const sql = sqlString.format('insert into user set ?', query);
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

const getTaskByQuery = (req: Request, res: Response, sql: string) =>
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
    let favorites: {
      id_task: string;
      id_user: string;
    }[] = [];
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

    const userId = (req.session as any)?.passport?.user;

    const favPromise = new Promise((resolve, reject) => {
      const sql = sqlString.format(
        'SELECT * FROM levsha.task_favorite where id_user = ? LIMIT 100;',
        [userId]
      );

      connection.query(sql, (err, result) => {
        if (err) reject(err);

        favorites = result;
        resolve(result);
      });
    });

    Promise.all([
      taskPromise,
      userPromise,
      districtPromise,
      ...imagePromises,
      favPromise,
    ])
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
              is_favorite: favorites.some((fav) => fav.id_task === task.uuid),
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

  return getTaskByQuery(req, res, sql);
});

app.get(basePath + '/user/task', checkAuthentication, (req, res) => {
  const userId = (req.session as any)?.passport?.user;

  const sql = sqlString.format(
    'select * from task where date_created > DATE_ADD(CURDATE(), INTERVAL -3 DAY) and is_deleted = 0 and user_id = ?',
    [userId]
  );

  return getTaskByQuery(req, res, sql);
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
    const fileName = uuidv4() + '.jpg';
    if (!req.file || !req.file.path) {
      return res.status(400).send({ message: 'No file uploaded.' });
    }

    const sourcePath = path.resolve(req.file.path);

    // Ensure the uploaded file is within the expected upload root
    if (!sourcePath.startsWith(uploadRoot)) {
      return res.status(400).send({ message: 'Invalid upload path.' });
    }

    fs.rename(
      sourcePath,
      path.join(uploadRoot, fileName),
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

      const favoritesPromise = new Promise((resolve, reject) => {
        const userId = (req.session as any)?.passport?.user;
        const sql = sqlString.format(
          'select count(id_user) from task_favorite where id_task = ? and id_user = ? limit 1',
          [req.params.task_id, userId]
        );

        connection.query(sql, (err, result) => {
          if (err) return reject({ ...err, sql });
          if (result) task.is_favorite = result[0]['count(id_user)'] == 1;
          if (result) task.is_favorite_debug = result;
          resolve(result);
        });
      });

      Promise.all([
        locationPromise,
        userPromise,
        categoryPromise,
        imagePromise,
        favoritesPromise,
      ])
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

          return res.status(200).send({
            uuid: taskId,
          });
        });
      } else {
        return res.status(200).send({
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

app.get(basePath + '/task/by_favorites', checkAuthentication, (req, res) => {
  const userId = (req.session as any)?.passport?.user;

  const sql = sqlString.format(
    'select * from task_favorite join task ON task.uuid = task_favorite.id_task where task_favorite.id_user = ? and task.date_created > DATE_ADD(CURDATE(), INTERVAL -3 DAY);',
    [userId]
  );

  return getTaskByQuery(req, res, sql);
});

app.all(basePath + '/task/category', (req, res) => {
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

app.all(
  basePath + '/task/item/:task_id/fav',
  checkAuthentication,
  (req, res) => {
    const id_task = req.params.task_id;
    const id_user = (req.session as any)?.passport?.user;

    if (req.query['value'] === 'true') {
      const sql = sqlString.format('insert into task_favorite set ?', {
        id_task,
        id_user,
      });

      connection.query(sql, (err, result) => {
        if (err) {
          return res.status(400).send({
            code: err.errno,
            type: err.code,
            message: err.sqlMessage,
          });
        }

        return res.json({
          taskId: id_task,
          userId: id_user,
          query: req.query,
          result: { ...result },
        });
      });
    } else {
      const sql = sqlString.format(
        'delete from task_favorite where id_task = ? AND id_user = ? limit 1',
        [id_task, id_user]
      );

      connection.query(sql, (err, result) => {
        if (err) {
          return res.status(400).send({
            code: err.errno,
            type: err.code,
            message: err.sqlMessage,
          });
        }

        return res.json({
          taskId: id_task,
          userId: id_user,
          query: req.query,
          result: { ...result },
        });
      });
    }
  }
);

/// USER
app.get(basePath + '/user/:uuid', (req, res) => {
  const userId = req.params.uuid;

  if (userId) {
    const query = sqlString.format(
      'select * from user where uuid = ? limit 1',
      [userId]
    );
    connection.query(query, (err, result) => {
      if (err) {
        return res.status(400).send({
          code: err.errno,
          type: err.code,
          message: err.sqlMessage,
        });
      }

      delete result[0].password_hash;

      res.status(200).json({ ...result[0], userId });
    });
  }
});

app.get(basePath + '/user/:uuid', (req, res) => {
  const userId = req.params.uuid;

  if (userId) {
    const query = sqlString.format(
      'select * from user where uuid = ? limit 1',
      [userId]
    );
    connection.query(query, (err, result) => {
      if (err) {
        return res.status(400).send({
          code: err.errno,
          type: err.code,
          message: err.sqlMessage,
        });
      }

      delete result[0].password_hash;

      res.status(200).json({ ...result[0], userId });
    });
  }
});

app.post(basePath + '/user/:uuid', checkAuthentication, (req, res) => {
  const userId = req.params.uuid;

  const userObject = {
    firstname: req.body.firstname,
    secondname: req.body.secondname,
    lastname: req.body.lastname,
    email: req.body.email,
    city_id: req.body.city.id,
  };

  if (userId) {
    const query = sqlString.format('update from set ? where uuid = ? limit 1', [
      userObject,
      userId,
    ]);
    connection.query(query, (err, result) => {
      if (err) {
        return res.status(400).send({
          code: err.errno,
          type: err.code,
          message: err.sqlMessage,
        });
      }

      res.status(200).json({ userId, result });
    });
  }
});

app.delete(basePath + 'user/:uuid', checkAuthentication, (req, res) => {
  const userId = req.params.uuid;

  const userObject = {
    is_deleted: 1,
    date_deleted: Date.now(),
  };

  if (userId) {
    const query = sqlString.format('update from set ? where uuid = ? limit 1', [
      userObject,
      userId,
    ]);
    connection.query(query, (err, result) => {
      if (err) {
        return res.status(400).send({
          code: err.errno,
          type: err.code,
          message: err.sqlMessage,
        });
      }

      res.status(200).json({ userId, result });
    });
  }
});

app.post(
  basePath + 'user/:uuid/image',
  checkAuthentication,
  uploadImageRateLimiter,
  (req, res) => {
    const userId = req.params.uuid;
    const fileName = uuidv4() + '.jpg';

    if (!req.file) {
      return res.status(400).send({ message: 'No file uploaded' });
    }

    const uploadRoot = path.resolve(uploadsPath);
    const targetPath = path.resolve(uploadRoot, uploadsRelativePath, fileName);

    if (!(targetPath === uploadRoot || targetPath.startsWith(uploadRoot + path.sep))) {
      return res.status(400).send({ message: 'Invalid upload path' });
    }

    const sourcePath = path.resolve(req.file.path);
    const tempUploadRoot = path.resolve(uploadRoot);
    if (!(sourcePath === tempUploadRoot || sourcePath.startsWith(tempUploadRoot + path.sep))) {
      return res.status(400).send({ message: 'Invalid source upload path' });
    }

    fs.rename(
      sourcePath,
      targetPath,
      (err) => {
        if (err) {
          res.status(500).send(err);
        } else {
          const query = {
            photo_url: uploadsRelativePath + fileName,
          };
          const sql = sqlString.format(
            'update user set ? where uuid = ? limit 1',
            [query, userId]
          );
          connection.query(sql, (err, result) => {
            if (err) {
              return res.status(400).send({
                code: err.errno,
                type: err.code,
                message: err.sqlMessage,
              });
            }

            return res.status(200).json({ userId, result });
          });
        }
      }
    );
  }
);

/// APPLICATION AVAILABILITY

app.get(basePath + '/ping', (req, res) => {
  return res.send('pong');
});

app.listen(serverPort, () => {
  const url = new URL(serverApi);
  url.port = `${serverPort}`;
  console.info(`Listening api ${url}`);
});
