/**
 * Controller responsible for handling the logic for Url login
 * (login in with a link, for now send by e-mail)
 */
 const authType = 'Url';

const passport          = require('passport');
const bcrypt            = require('bcrypt');
const saltRounds        = 10;
const hat               = require('hat');
const login             = require('connect-ensure-login');
const User              = require('../../models').User;
const ActionLog         = require('../../models').ActionLog;
const tokenUrl          = require('../../services/tokenUrl');
const emailService      = require('../../services/email');
const authUrlConfig     = require('../../config/auth').get('Url');
const userService       = require('../../services/user');
const settings          = require('../../config/settings');

const logSuccessFullLogin = (req) => {
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

  const values = {
    method: 'post',
    name: 'Url',
    value: 'login',
    clientId: req.client.id,
    userId: req.user.id,
    ip: ip
  };

  return new ActionLog(values).save();
}

exports.login  = (req, res) => {
  const config = req.client.config ? req.client.config : {};
  const configAuthType = config.authTypes && config.authTypes[authType] ? config.authTypes[authType] : {};

  res.render('auth/url/login', {
    clientId: req.query.clientId,
    client: req.client,
    redirectUrl: encodeURIComponent(req.query.redirect_uri),
    title: configAuthType && configAuthType.title ? configAuthType.title : false,
    description: configAuthType && configAuthType.description ?  configAuthType.description : false,
    label: configAuthType && configAuthType.label ?  configAuthType.label : false,
    helpText: configAuthType && configAuthType.helpText ? configAuthType.helpText : false,
    buttonText: configAuthType && configAuthType.buttonText ? configAuthType.buttonText : false,
    showUserOptIn: settings.showUserOptIn(config),
    userOptInText: settings.getUserOptInText(config)
  });
};

exports.authenticate  = (req, res) => {
  res.render('auth/url/authenticate', {
    clientId: req.query.clientId,
    client: req.client,
    redirectUrl: encodeURIComponent(req.query.redirect_uri)
  });
};

exports.register = (req, res, next) => {
  res.render('auth/url/register', {
   token: req.query.token,
   user: req.user,
   client: req.client,
   clientId: req.client.clientId
  });
}

const handleSending = (req, res, next) => {

  tokenUrl.invalidateTokensForUser(req.user.id)
    .then(() => { return tokenUrl.format(req.client, req.user, req.redirectUrl); })
    .then((tokenUrl) => { return sendEmail(tokenUrl, req.user, req.client); })
    .then((result) => {
      req.flash('success', {msg: 'De e-mail is verstuurd naar: ' + req.user.email});
      res.redirect(req.header('Referer') || '/login-with-email-url');
    })
    .catch((err) => {
      console.log('e0mail error', err);
      req.flash('error', {msg: 'Het is niet gelukt om de e-mail te versturen!'});
      res.redirect(req.header('Referer') || '/login-with-email-url');
    });
}

/**
 * Send email
 */
const sendEmail = (tokenUrl, user, client) => {
  const clientConfig = client.config ? client.config : {};
  const authTypeConfig = clientConfig.authTypes && clientConfig.authTypes.Url  ? clientConfig.authTypes.Url  : {};
  const emailTemplateString = authTypeConfig.emailTemplate ? authTypeConfig.emailTemplate : false;
  const emailSubject = authTypeConfig.emailSubject ? authTypeConfig.emailSubject : 'Inloggen bij ' + client.name;
  const emailHeaderImage = authTypeConfig.emailHeaderImage ? authTypeConfig.emailHeaderImage : false;
  const emailLogo = authTypeConfig.emailLogo ? authTypeConfig.emailLogo : false;


  return emailService.send({
    toName: (user.firstName + ' ' + user.lastName).trim(),
    toEmail: user.email,
    fromEmail: clientConfig.fromEmail,
    fromName: clientConfig.fromName,
    subject: emailSubject,
    templateString: emailTemplateString,
    template: 'emails/login-url.html',
    variables: {
      tokenUrl: tokenUrl,
      firstName: user.firstName,
      clientUrl: client.mainUrl,
      clientName: client.name,
      headerImage: emailHeaderImage,
      logo: emailLogo
    }
  });
}


exports.postLogin = async (req, res, next) => {
  const clientConfig = req.client.config ? req.client.config : {};
  const redirectUrl =  clientConfig && clientConfig.emailRedirectUrl ? clientConfig.emailRedirectUrl : encodeURIComponent(req.query.redirect_uri);
  req.redirectUrl = redirectUrl;

  /**
   * Check if user exists
   */
  try {
    let user = await userService.get(req.body.email);

    if (user) {
      await userService.addOptins(user.id, [req.body.optin_email], req.client.id);
      req.user = user.serialize();
      return handleSending(req, res, next);
    }

    /**
     * If active user is already set, the user is already logged in
     * If email is not set it means they as anonymous user
     * Add the submitted email to anonymous user
     * If already a user with that email, ignore the anonymous user and login via existing user
     */
    if (req.user && !req.user.email && !user) {
      let user = await userService.update(req.user, req.body.email, [req.body.optin_email]);
      await userService.addOptins(user.id, [req.body.optin_email], req.client.id);
      req.user = user.serialize();
      return handleSending(req, res, next);
    }

    user = await userService.create(req.body.email, [req.body.optin_email]);
    await userService.addOptins(user.id, [req.body.optin_email], req.client.id);

    req.user = user.serialize();
    handleSending(req, res, next);

  } catch (error) {
    console.log('===> err', error);
    req.flash('error', {msg: 'Het is niet gelukt om de e-mail te versturen!'});
    res.redirect(req.header('Referer') || authUrlConfig.loginUrl);
  }
}


exports.postRegister = (req, res, next) => {
   const { firstName, lastName, postcode, token } = req.body;
   const userModel = req.userModel;

   /**
    * Set Values for user; validation is taken care of in middleware
    */
   userModel.set('firstName', firstName);
   userModel.set('lastName', lastName);
   userModel.set('postcode', postcode);

   /**
    * After succesfull registration redirect to token login url, for automagic login
    */
   userModel
   .save()
   .then((userReponse) => {
     const user = userReponse.serialize();
     res.redirect(tokenUrl.getUrl(user, req.client, token));
   })
   .catch((err) => { next(err) });

};


exports.postAuthenticate =  (req, res, next) => {
 passport.authenticate('url', { session: true }, function(err, user, info) {
   if (err) { return next(err); }
   const redirectUrl = req.query.redirect_uri ? encodeURIComponent(req.query.redirect_uri) : req.client.redirectUrl;


   // Redirect if it fails to the original e-mail screen
   if (!user) {
     req.flash('error', {msg: 'De url is geen geldige login url, wellicht is deze verlopen'});
     return res.redirect(`/auth/url/login?clientId=${req.client.clientId}&redirect_uri=${redirectUrl}`);
   }

   req.logIn(user, function(err) {
     if (err) { return next(err); }

     return tokenUrl.invalidateTokensForUser(user.id)
      .then((response) => {
        const redirectToAuthorisation = () => {
          // Redirect if it succeeds to authorize screen
          //check if allowed url will be done by authorize screen
          const authorizeUrl = `/dialog/authorize?redirect_uri=${redirectUrl}&response_type=code&client_id=${req.client.clientId}&scope=offline`;
          return res.redirect(authorizeUrl);
        }

        req.brute.reset(() => {
            //log the succesfull login
            logSuccessFullLogin(req)
              .then (() => { redirectToAuthorisation(); })
              .catch (() => { redirectToAuthorisation(); });
        });
      })
      .catch((err) => {
        next(err);
      });
   });

 })(req, res, next);
};
