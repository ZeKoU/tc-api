/* jslint node: true */
/*
 * Copyright (C) 2013 TopCoder Inc., All Rights Reserved.
 *
 * @version 1.1
 * @author vangavroche, TCSASSEMBLER
 * changes in 1.1:
 * - add cache support (add preCacheProcessor and postCacheProcessor)
 */
"use strict";
/**
 * Module dependencies.
 */
var async = require('async');
var _ = require('underscore');
var crypto = require('crypto');
var configs = require("../config.js");
var jwtlib = require('jsonwebtoken');
var dao = require('./dataAccess.js');

/**
 * Define the config to get the API Host from the environment variables.
 */
var config = {
    apiHost: process.env.TC_API_HOST || 'api.topcoder.com'
};

/**
 * Helper function to get the header value from the request object
 * @param {Object} req The request from where the header is obtained
 * @param {String} name The name of the header.
 */
var getHeader = function (req, name) {
    name = name.toLowerCase();
    switch (name) {
    case 'referer':
    case 'referrer':
        return req.headers.referrer || this.headers.referer;
    default:
        return req.headers[name];
    }
};


/**
 * Expose the middleware function to add the pre-processor for authentication via Oauth.
 *
 * @param {Object} api The api object used to access the infrastructure.
 * @param {Function<err>} next The callback function
 */
exports.middleware = function (api, next) {
    var databaseName = 'common_oltp';
    var auth0Processor,
        authorize,
        dbConnection;

     /**
     * Helper function to decide if login is social, given the JWT object
     * @param {Object} jwt JSON Web Token with social identities
     */
     function isSocialLogin(jwt){
        var identities = jwt.identities;
        if(!identities || identities.length === 0) {
            api.log("No identities detected in JWT!", "error");
            return false;
        } else {
            for(var identity in identities){
                var ident = identities[identity];
                api.log("Identity: " + JSON.stringify(ident), "debug");
                if(ident.isSocial === true) {
                    api.log("Social identity detected!", "debug");
                    return true;
                }
            }
            api.log("Normal (non-social) identity detected!", "debug");
            return false;
        }
     }

     /**
     * Helper function to get user_id from identity contained within JSON Web Token
     * @param {Object} jwt JSON Web Token with social identities
     */
     function getSocialUserId(jwt) {
        var identities = jwt.identities;
        if( !identities || identities.length === 0) {
            api.log("No identities detected in JWT!", "error");
            return false;
        } else {
            for(var identity in identities) {
                var ident = identities[identity];
                if(ident.isSocial === true) {
                    return ident.user_id;
                }
            }
        }
        return null;
     }

     /**
     * Helper function to query user_id from user_social_login table
     * @param {Integer} providerId ID of Social Provider
     * @param {String}  social_user_id This is user_id as defined in social Auth0 Identity
     * @param {Function<error, result>} cb Callback for error or result
     */
     function queryUserId(providerId, social_user_id, cb) {
        var queryName = "get_user_id";
        var dbConnectionMap = { };
        dbConnectionMap[databaseName] = dbConnection;
        var sqlParameters = { social_user_id: social_user_id, social_login_provider_id: providerId };
        api.dataAccess.executeQuery(queryName, sqlParameters, dbConnectionMap, function (error, result) {
            api.log("SQL execute result returned", "debug");
            if (error) {
                api.log("Error occurred: " + error + " " + (error.stack || ''), "error");
                cb(error, null);
            } else {
                if(result.length > 0){
                    //api.log("Result: " + JSON.stringify(result[0]));
                    cb(null, result[0].user_id);
                } else {
                    //api.log("No result in query!", "debug");
                    cb(null, null);
                }
            }
        });
    };

    /**
    * Helper function to query handle from the user table
    * @param {Integer} user_id ID of the user
    * @param {Function<error, result>} cb Callback for error or result
    */
    function queryHandle(user_id, cb) {
        var queryName = "get_user_handle";
        var dbConnectionMap = { };
        dbConnectionMap[databaseName] = dbConnection;
        var sqlParameters = { user_id: user_id};
        api.dataAccess.executeQuery(queryName, sqlParameters, dbConnectionMap, function (error, result) {
            api.log("SQL execute result returned", "debug");
            if (error) {
                api.log("Error occurred: " + error + " " + (error.stack || ''), "error");
                cb(error, null);
            } else {
                if(result.length > 0){
                    //api.log("Result: " + JSON.stringify(result[0]));
                    cb(null, result[0].handle);
                } else {
                    //api.log("No result in query!", "debug");
                    cb(null, null);
                }
            }
        });
    };

    /**
    * Helper function to check if user has admin access level
    * @param {Integer} user_id The id of user being checked for admin access
    * @oaram {Function<error, result>}  callback Callback function returning error or result
    */
    function queryIsAdmin(user_id, callback) {
        var queryName = "check_is_admin";
        var dbConnectionMap = { };
        dbConnectionMap[databaseName] = dbConnection;
        var sqlParameters = { login_id: user_id, user_id: user_id};
        api.dataAccess.executeQuery(queryName, sqlParameters, dbConnectionMap, function (error, result) {
            api.log("SQL execute result returned", "debug");
            if (error) {
                api.log("Error occurred: " + error + " " + (error.stack || ''), "error");
                callback(error, null);
            } else {
                if(result.length > 0){
                    //api.log("Result: " + JSON.stringify(result[0]));
                    var isAdmin = (result[0].security_status_id === 1 ) ? true : false;
                    callback(null, isAdmin );
                } else {
                    //api.log("No result in query!", "debug");
                    callback(null, false);
                }
            }
        });
    }

    /**
    * Helper function to connect to database
    * @param {Function<error>} callback The callback function.
    */
    function dbConnect(callback){

        if(!dbConnection){
            api.log("Creating new connection for Auth0 middleware.", "debug");
            dbConnection = api.dataAccess.createConnection(databaseName);
        }

        if(!dbConnection.isConnected()){
            api.log("Connecting to database for Auth0 middleware.", "debug");
            // connnect to the connection
            dbConnection.on('error', function (err) {
                dbConnection.disconnect();
                api.log("Database connection to " + databaseName + " error: " + err + " " + (err.stack || ''), 'error');
            }).initialize().connect(function (err) {
                if (err) {
                    dbConnection.disconnect();
                    api.log("Database " + databaseName + " cannot be connected: " + err + " " + (err.stack || ''), 'error');
                    callback(err);
                } else {
                    api.log("Database " + databaseName + " connected", 'info');
                    callback();
                }
            });
        }
        callback();
    }

    function handleAccessLevel(user_id, connection, done){
        queryIsAdmin(user_id, function (e, isAdmin) {
            if (e) {
                api.log("Error checking if user is admin!" , "debug");
                done("Error:" + e, 500);
            } else {
                queryHandle(user_id, function (e1, handle) {
                    if (e1) {
                        api.log("Error querying handle: " + e1, "debug");
                        done("Error querying handle: " + e1, 500);
                    } else {
                        if(handle){
                            connection.caller.handle = handle;
                            if( isAdmin === true ){
                                connection.caller.accessLevel = configs.configData.userRoles.ADMIN;
                            } else if ( isAdmin === false ) {
                                connection.caller.accessLevel = configs.configData.userRoles.BASIC;
                            }
                        }
                        done(null, 200);
                    }
                });
            }
        });
    }

     /**
     * Helper function to get provider id persisted in database from configuration mapping
     * @param {String} user_id Full user_id field of JSON Web Token
     */
     function getProviderId(user_id) {
        var providerString = user_id.split("|")[0];
        if (providerString.indexOf("google") > -1) {
            return configs.configData.auth0.socialProviders.GOOGLE_PROVIDER;
        } else if (providerString.indexOf("facebook") > -1) {
            return configs.configData.auth0.socialProviders.FACEBOOK_PROVIDER;
        } else if (providerString.indexOf("twitter") > -1) {
            return configs.configData.auth0.socialProviders.TWITTER_PROVIDER;
        } else if (providerString.indexOf("github") > -1) {
            return configs.configData.auth0.socialProviders.GITHUB_PROVIDER;
        } else if (providerString.indexOf("salesforce") > -1) {
            return configs.configData.auth0.socialProviders.SALESFORCE_PROVIDER;
        } else if (providerString.indexOf("ldap") > -1) { //FIXME : How to detect LDAP mapping 
            return configs.configData.auth0.socialProviders.ENTERPRISE_LDAP_PROVIDER;
        }
     };


     /**
     * Helper function to authorize request, given the header and the action scope.
     *
     * @param {Object} connection ActionHero connection object
     * @param {String} authHeader The authorization header value
     * @param {String} actionScope The permission scope of the given action
     * @param {Function<err, status>} done The callback function
     */
    authorize = function (connection, authHeader, done) {

        if (!authHeader || authHeader.trim().length === 0) {
            //Allow anonymous access
            connection.caller.accessLevel = configs.configData.userRoles.ANON;
            done(null, 200);
        } else {
            api.log("Parsing JWT...", "debug");
            var token = authHeader.split(" ");
            if (token.length !== 2) {
                done("Error: Invalid token! Required format: Bearer <json_web_token>", 400);//Bad request
                return;
            } else if (token[0] !== "Bearer") {
                done("Error: Invalid token. Bearer token expected!", 400);//Bad request
                return;
            }
            var jwt = token[1];
            var clientSecret = new Buffer(configs.configData.auth0.jwtSignatureKey, "base64");
            jwtlib.verify(jwt, clientSecret, function (error, decodedToken) {
                if (error) {
                    api.log("Error decoding JWT: " + error, "error");
                    done(error + ". Please check passed JSON Web Token!", 400); //Bad request
                } else {
                    api.log("Decoded JWT: " + JSON.stringify(decodedToken) , "debug");
                    var social = isSocialLogin(decodedToken);
                    if(social===true){
                        //Handle social provider id
                        var providerId = getProviderId(decodedToken.user_id);
                        //api.log("Social provider ID: " + providerId, "debug");
                        var social_user_id = getSocialUserId(decodedToken);
                        //api.log("Social user_id: " + social_user_id, "debug");
                        dbConnect(function (err) {
                            if (err) {
                                done(err, 500);
                            } else {
                                queryUserId(providerId, social_user_id, function (e, user_id) {
                                    if(e) {
                                        api.log("Error querying user_id: " + e, "debug");
                                        done(e, 500);
                                    } else {
                                       connection.caller.userId = user_id;
                                       handleAccessLevel(user_id, connection, done);
                                    }
                                });
                            }
                        });
                    } else {
                        dbConnect(function (err) {
                            if (err) {
                                done(err, 500);
                            } else {
                                var user_id = decodedToken.sub.split("|")[1];
                                connection.caller.userId = user_id;
                                handleAccessLevel(user_id, connection, done);
                            }
                        });
                    }
                }
            });
        }
    };

    /**
     * The pre-processor that check the action via Auth0.
     * Only the actions that have configured "auth0Protected:true" are checked here
     *
     * @param {Object} connection The connection object for the current request
     * @param {Object} actionTemplate The metadata of the current action object
     * @param {Function<connection, toRender>} next The callback function
     */
    auth0Processor = function (connection, actionTemplate, next) {
        connection.caller = {};
        if (actionTemplate.auth0Protected === true) {
            api.log("Auth0 pre-processor invoked!", "debug");
            authorize(connection, getHeader(connection.rawConnection.req, 'Authorization'), function (error, statusCode) {
                if (error) {
                    api.log("Auth0 pre-processor error!", "debug");
                    connection.error = error;
                    connection.rawConnection.responseHttpCode = statusCode;
                    next(connection, false);
                } else {
                    api.log("Auth0 pre-processor finnished!", "debug");
                    next(connection, true);
                }
            });
        } else {
            next(connection, true);
        }
    };

    /**
     * Create unique cache key for given connection.
     * Key depends on action name and query parameters (connection.params).
     *
     * @param {Object} connection The connection object for the current request
     * @return {String} the key
     */
    function createCacheKey(connection) {
        var sorted = [], prop, val, json;
        for (prop in connection.params) {
            if (connection.params.hasOwnProperty(prop)) {
                val = connection.params[prop];
                if (_.isString(val)) {
                    val = val.toLowerCase();
                }
                sorted.push([prop, val]);
            }
        }
        sorted.sort(function (a, b) {
            return a[1] - b[1];
        });
        json = JSON.stringify(sorted);
        return crypto.createHash('md5').update(json).digest('hex');
    }

    /**
     * Get cached value for given connection. If object doesn't exist or is expired then null is returned.
     *
     * @param {Object} connection The connection object for the current request
     * @param {Function<err, value>} callback The callback function
     * @since 1.1
     */
    /*jslint unparam: true */
    function getCachedValue(connection, callback) {
        var key = createCacheKey(connection);
        api.cache.load(key, function (err, value) {
            //ignore err
            //err can be only "Object not found" or "Object expired"
            callback(null, value);
        });
    }

    /**
     * The pre-processor that check the cache.
     * If cache exists then cached response is returned.
     *
     * @param {Object} connection The connection object for the current request
     * @param {Object} actionTemplate The metadata of the current action object
     * @param {Function<connection, toRender>} next The callback function
     * @since 1.1
     */
    function preCacheProcessor(connection, actionTemplate, next) {
        //by default enabled
        if (actionTemplate.cacheEnabled === false) {
            next(connection, true);
            return;
        }

        getCachedValue(connection, function (err, value) {
            if (value) {
                api.log('Returning cached response', 'debug');
                connection.response = value;
                next(connection, false);
            } else {
                next(connection, true);
            }
        });
    }

    /**
     * The post-processor that save response to cache.
     * Cache is not saved if error occurred.
     *
     * @param {Object} connection The connection object for the current request
     * @param {Object} actionTemplate The metadata of the current action object
     * @param {Boolean} toRender The flag whether response should be rendered
     * @param {Function<connection, toRender>} next The callback function
     * @since 1.1
     */
    function postCacheProcessor(connection, actionTemplate, toRender, next) {
        //by default enabled
        if (actionTemplate.cacheEnabled === false) {
            next(connection, toRender);
            return;
        }

        async.waterfall([
            function (cb) {
                getCachedValue(connection, cb);
            }, function (value, cb) {
                if (value || connection.response.error) {
                    cb();
                    return;
                }
                var response = _.clone(connection.response),
                    lifetime = actionTemplate.cacheLifetime || api.configData.general.defaultCacheLifetime,
                    key = createCacheKey(connection);
                delete response.serverInformation;
                delete response.requestorInformation;
                api.cache.save(key, response, lifetime, cb);
            }
        ], function (err) {
            if (err) {
                api.helper.handleError(api, connection, err);
            }
            next(connection, toRender);
        });
    }

    api.actions.preProcessors.push(auth0Processor);
    api.actions.preProcessors.push(preCacheProcessor);
    api.actions.postProcessors.push(postCacheProcessor);
    next();
};