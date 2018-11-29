const login                    = require('connect-ensure-login');
const ExpressBrute 					   = require('express-brute');

//CONTROLERS
const oauth2Controller 				 = require('./controllers/oauth/oauth2');
const tokenController          = require('./controllers/oauth/token');
const userController           = require('./controllers/user/user');
const adminUserController      = require('./controllers/admin/user');
const adminClientController    = require('./controllers/admin/client');
const adminRoleController      = require('./controllers/admin/role');
const adminCodeController      = require('./controllers/admin/code');

//AUTH CONTROLLERS
const authChoose	 						 = require('./controllers/auth/choose');
const authUrl 		 						 = require('./controllers/auth/url');
const authForgot							 = require('./controllers/auth/forgot');
const authDigiD							 	 = require('./controllers/auth/digid');
const authLocal							   = require('./controllers/auth/local');
const authCode							 	 = require('./controllers/auth/code');

//MIDDLEWARE
const adminMiddleware          = require('./middleware/admin');
const clientMw      				   = require('./middleware/client');
const userMw           				 = require('./middleware/user');
const tokenMw                  = require('./middleware/token');
const bruteForce 							 = require('./middleware/bruteForce').default;
const authMw                   = require('./middleware/auth');
const passwordResetMw          = require('./middleware/passwordReset');
const roleMw                   = require('./middleware/role');
const codeMw                   = require('./middleware/code');

module.exports = function(app){
  app.get('/', authLocal.index);

	/**
	 * Login routes for clients,
	 * checks if one or more options of authentications is available
	 * and either shows choice or redirects if one option
	 */
	app.get('/login', bruteForce.prevent, clientMw.addOne, authChoose.index);

	/**
	 * Shared middleware for all auth routes, adding client and per
	 */
	app.use('/auth', [bruteForce.prevent, clientMw.addOne]);

	/**
	 * Login & register with local login
	 */
	//shared middleware
	app.use('/auth/local', [clientMw.setAuthType('Local'), clientMw.validate]);

	//routes
	app.get('/auth/local/login', authLocal.login);
	app.post('/auth/local/login', authMw.validateLogin, authLocal.postLogin);
	app.get('/auth/local/register', authLocal.register);
	app.post('/auth/local/register', userMw.validateUser, authLocal.postRegister);

	/**
	 * Deal with forgot password
	 */
	app.get('/auth/local/forgot', authForgot.forgot);
	app.post('/auth/local/forgot', authForgot.postForgot);
	app.get('/auth/local/reset', passwordResetMw.validate, authForgot.reset);
	app.post('/auth/local/reset', passwordResetMw.validate, userMw.addOne, userMw.validateEmail, autMw.validatePassword, authForgot.postReset);

	/**
	 * Auth routes for URL login
	 */
	 // shared middleware
	app.use('/auth/url', [clientMw.setAuthType('Url'), clientMw.validate]);

	// routes
	app.get('/auth/url/login', authUrl.login);
	app.post('/auth/url/login', authUrl.postLogin);
	app.get('/auth/url/authenticate', authUrl.authenticate);
	app.get('/auth/url/register', authUrl.register);
	app.post('/auth/url/register', authUrl.postRegister);

	/**
	 * Auth routes for DigiD
	 * @TODO: available routes
	 */
	app.use('/auth/digid', [clientMw.setAuthType('DigiD'), clientMw.validate]);
 	app.get('/auth/digid/login', authDigiD.login);
  app.post('/auth/digid/login', authDigiD.postLogin);

	/**
	 * Auth routes for UniqueCode
	 */
	app.use('/auth/code', [clientMw.setAuthType('UniqueCode'), clientMw.validate]);
	app.get('/auth/code/login', authCode.login);
	app.post('/auth/code/login', authCode.postLogin);

	/**
	 * Register extra info;
	 * In case client specifies required fields
	 */
//	app.get('/register/info')

	/**
	 * Logout (all types :))
	 */
	app.get('/logout', clientMw.addOne, authLocal.logout);

	/**
	 * Show account, add client, but not obligated
	 */
	app.use('/user', [login.ensureLoggedIn(), clientMw.addOne]);
  app.get('/account', userController.account);
  app.post('/account', userMw.validateUser, userController.postAccount);
  app.post('/password', userMw.validatePassword, userController.postAccount);

  app.get('/dialog/authorize', oauth2Controller.authorization);
  app.post('/dialog/authorize/decision', bruteForce.prevent, oauth2Controller.decision);
  app.post('/oauth/token', bruteForce.prevent, oauth2Controller.token);
  app.get('/oauth/token', oauth2Controller.token);

  app.get('/api/userinfo', userController.info);
  // app.get('/api/clientinfo', client.info);

  // Mimicking google's token info endpoint from
  // https://developers.google.com/accounts/docs/OAuth2UserAgent#validatetoken
  app.get('/api/tokeninfo', tokenController.info);

  // Mimicking google's token revoke endpoint from
  // https://developers.google.com/identity/protocols/OAuth2WebServer
  app.get('/api/revoke', tokenController.revoke);

  /**
   * Admin user routes
   */

  //shared middlware for all admin routes
  app.use('/admin/client', [login.ensureLoggedIn(), adminMiddleware.ensure]);

  app.get('/admin/users', userMw.withAll, adminUserController.all);
  app.get('/admin/user/:userId', userMw.withOne, adminUserController.edit);
  app.get('/admin/user', adminUserController.new);
  app.post('/admin/user', adminUserController.create);
  app.post('/admin/user/:userId',  userMw.withOne, adminUserController.update);

  /**
   * Admin client routes
   */
  app.get('/admin/clients', clientMw.withAll, adminClientController.all);
  app.get('/admin/client/:clientId', clientMw.withOne, adminClientController.edit);
  app.get('/admin/client', adminClientController.new);
  app.post('/admin/client', adminClientController.create);
  app.post('/admin/client/:clientId', clientMw.withOne, adminClientController.update);

  /**
   * Admin role routes
   */
  app.get('/admin/roles', roleMw.withAll, adminClientController.all);
  app.get('/admin/role/:roleId', roleMw.withOne, adminClientController.edit);
  app.get('/admin/role', adminRoleController.new);
  app.post('/admin/role', adminRoleController.create);
  app.post('/admin/role/:roleId', clientMw.withOne, adminRoleController.update);

  /**
   * Admin code routes
   */
  app.get('/admin/codes', codeMw.withAll, adminCodeController.all);
  app.get('/admin/code', adminCodeController.new);
  app.get('/admin/code/bulk', adminCodeController.bulk);
  app.post('/admin/code/bulk', adminCodeController.postBulk);
  app.post('/admin/code', adminCodeController.create);
  app.post('/admin/code/destroy/:codeId', adminCodeController.destroy);

  //  app.get('/admin/code/:codeId', codeMw.withOne, adminCodeController.edit);

//  app.post('/admin/code/:roleId', codeMw.withOne, adminCodeController.update);


}
