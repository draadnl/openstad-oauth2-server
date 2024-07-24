// Update with your config settings.
require('dotenv').config();

const connection = {
  host:     process.env.DB_HOST,
  database: process.env.DB_NAME,
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
};

if (process.env.MYSQL_CA_CERT && process.env.MYSQL_CA_CERT.trim && process.env.MYSQL_CA_CERT.trim()) {
	connection.ssl = {
		rejectUnauthorized: true,
		ca: [ process.env.MYSQL_CA_CERT ]
	}
}

module.exports = {
  development: {
    client: 'mysql',
    connection,
    migrations: {
      directory: __dirname + '/knex/migrations',
    },
    seeds: {
      directory: __dirname + '/knex/seeds'
    },
    pool: { min: 0, max: 10 }
  },
  test: {
    client: 'sqlite3',
    connection: ':memory:',
    useNullAsDefault: true,
    migrations: {
      directory: __dirname + '/knex/migrations',
    },
    seeds: {
      directory: __dirname + '/knex/seeds'
    },
    pool: { min: 0, max: 10 }
  },

  production: {
    client: 'mysql',
    connection,
    migrations: {
      directory: __dirname + '/knex/migrations',
    },
    seeds: {
      directory: __dirname + '/knex/seeds'
    },
    pool: { min: 0, max: 10 }
  }

};
