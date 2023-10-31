const Promise = require('bluebird');
const LoginToken = require('../models').LoginToken;
const appUrl = process.env.APP_URL;
const hat = require('hat');

/**
 *
 */
const getUrl = (user, client, token, redirectUrl) => {
  const slug = 'auth/url/authenticate';
  return `${appUrl}/${slug}?token=${token}&clientId=${client.clientId}&redirect_uri=${redirectUrl}`;
}

const getAdminUrl = (user, client, token, redirectUrl) => {
  const slug = 'auth/admin/authenticate';
  return `${appUrl}/${slug}?token=${token}&clientId=${client.clientId}&redirect_uri=${redirectUrl}`;
}

exports.format = (client, user, redirectUrl, admin) => {
  return new Promise((resolve, reject) =>  {
    const token = hat();

    new LoginToken({
      userId: user.id,
      token: token
    })
    .save()
    .then((loginToken) => {
      const url = admin ? getAdminUrl(user, client, token, redirectUrl) : getUrl(user, client, token, redirectUrl);
      resolve(url);
    })
    .catch((err) => {
      reject(err);
    });
  });
}

exports.getUrl = getUrl;

exports.invalidateTokensForUser = (userId) => {
  return new Promise((resolve, reject) => {
    resolve();
    /*if (!userId) {
      resolve();
    } else {
      LoginToken
      .where({userId: userId})
      .save(
          {valid: false},
          {method: 'update', patch: true}
       )
       .then(() => { resolve(); })
       .catch(() => { resolve(); })
     }*/
  });

}
