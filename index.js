/**************************************************/
/**********     Node Authentication     ***********/
/*
/* This module supports streamlined Passport authentication.
/*
/**************************************************/

/**************************************************/
/***************     Constants     ****************/
/**************************************************/
var CONFIG_PATH = 'evernaut-node-authentication';
var CONFIG_PATH_STRATEGIES = (CONFIG_PATH + '.strategies');

/**************************************************/
/****************     Imports     *****************/
/**************************************************/
var passport = require('passport');

// Suppress config warning
if (typeof(process.env.SUPPRESS_NO_CONFIG_WARNING) !== 'undefined') {
	process.env.SUPPRESS_NO_CONFIG_WARNING = 'y';
}
var config = require('config');

/**************************************************/
/**********     Configure Strategies     **********/
/**************************************************/
var retrieveStrategyAuthenticationOptions = function(strategy) {
	var authenticationOptions;
	if ('authenticationOptions' in strategy) {
		authenticationOptions = strategy.authenticationOptions;
	} else {
		authenticationOptions = {};
	}
	return authenticationOptions;
};

var configureStrategies = function() {
	var strategiesConfig = config.get(CONFIG_PATH_STRATEGIES);
	var strategies = {};

	// Setup each strategy in the config
	if ('amazon' in strategiesConfig) {
		strategies.amazon = {
			name: 'amazon',
			module: require('passport-amazon').Strategy,
			authenticationOptions: config.util.extendDeep(
				{ scope: ['profile'] },
				retrieveStrategyAuthenticationOptions(strategiesConfig.amazon)
			)
		};
	}
	if ('facebook' in strategiesConfig) {
		strategies.facebook = {
			name: 'facebook',
			module: require('passport-facebook').Strategy,
			authenticationOptions: retrieveStrategyAuthenticationOptions(strategiesConfig.facebook)
		};
	}
	if ('google' in strategiesConfig) {
		strategies.google = {
			name: 'google',
			module: require('passport-google-oauth').OAuth2Strategy,
			authenticationOptions: config.util.extendDeep(
				{ scope: 'https://www.googleapis.com/auth/plus.login' },
				retrieveStrategyAuthenticationOptions(strategiesConfig.google)
			)
		};
	}

	for (strategyName in strategies) {
		var strategy = strategies[strategyName];
		var strategyConfig = strategiesConfig[strategyName];

		strategy.moduleOptions = {
			clientID: strategyConfig.clientId,
			clientSecret: strategyConfig.clientSecret,
			callbackURL: strategyConfig.callbackUrl,
	        passReqToCallback: true
		};
		strategy.callbackOptions = strategyConfig.callbackOptions || {};
	}

	return strategies;
}

/**************************************************/
/****************     Exports     *****************/
/**************************************************/
module.exports = function(app, functions, options) {
	// Allow defaults via config AND options
	options = options || {};
	config.util.setModuleDefaults(CONFIG_PATH, options);

	/****************     Functions    ****************/
	var authenticationVerificationCallback = functions.authenticationVerificationCallback;
	var authenticationRouteAuthenticateCallback = functions.authenticationRouteAuthenticateCallback;
	var authenticationCallbackRouteHandler = functions.authenticationCallbackRouteHandler;
	var logoutHandler = functions.logoutHandler;
	var serializeUser = functions.serializeUser;
	var deserializeUser = functions.deserializeUser;

	/***************     Strategies    ****************/
	var strategies = configureStrategies();

	/***********     User Serialization    ************/
	passport.serializeUser(serializeUser);
	passport.deserializeUser(deserializeUser);

	/***************     Middleware     ***************/
	app.use(passport.initialize());
	app.use(passport.session());

	/*****************     Routes     *****************/
	for (strategyName in strategies) {
		var strategy = strategies[strategyName];

		// Initialization
		passport.use(
			new strategy.module(strategy.moduleOptions, authenticationVerificationCallback)
		);

		// Authentication Route
		(function(strategy) {
			app.get(config.get(CONFIG_PATH_STRATEGIES + '.' + strategy.name + '.authenticationUrl'), function(req, res, next) {
				passport.authenticate(strategy.name, strategy.authenticationOptions, function(err, user, info) {
					process.nextTick(function() {
						authenticationRouteAuthenticateCallback(err, user, info, req, res, next);
					});
				})(req, res, next);
			});
		})(strategy);

		// Authentication Callback Route
		(function(strategy) {
			app.get(config.get(CONFIG_PATH_STRATEGIES + '.' + strategy.name + '.callbackUrl'),
				passport.authenticate(strategy.name, strategy.callbackOptions),
				authenticationCallbackRouteHandler
			);
		})(strategy);
	}

	app.get(config.get(CONFIG_PATH + '.logoutUrl'), logoutHandler);
};