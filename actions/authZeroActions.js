/*jslint node: true */
/*
 * Copyright (C) 2013 TopCoder Inc., All Rights Reserved.
 *
 * @version 1.1
 * @author ZeKoU
 * @changes from 1.0
 * merged with Member Registration API
 */
'use strict';

/**
 * This is dummy function that actually gets any auth0 protected resource.
 *
 * @param {Object} api The api object that is used to access the global infrastructure
 * @param {Object} connection The connection object for the current request
 * @param {Function} next The callback to be called after this function is done
 */
var getSecuredResource = function (api, connection, next) {
    api.log("Executing dummy auth0 api request!");

    connection.response = [connection.caller];
    next(connection, true);
};

exports.action = {
    name: "authZeroActions",
    description: "authZeroActions",
    inputs: {
        required: [],
        optional: []
    },
    blockedConnectionTypes: [],
    auth0Protected: true,
    cacheEnabled: false, //Disabled for Auth0 testing because consecutive hits would return
                         //same caller JSON object no matter if Authorization header changed or not.
    //transaction : 'read', // this action is read-only
    //databases : ['tcs_catalog'],
    outputExample: {},
    version : 'v2',
    run: function(api, connection, next) {
        //if (this.dbConnectionMap) {
            api.log("Execute authZeroActions#run", 'debug');
            getSecuredResource(api, connection, next);
            next(connection, true);
        //} else {
        //    api.helper.handleNoConnection(api, connection, next);
        //}

    }
};