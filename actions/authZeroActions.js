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
    var ret = [];
    ret.push({
        username: "Foo",
        password: "Bar",
        description: "Demo API protected by Auth0"
    });
    connection.response = ret;
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
    outputExample: {},
    version: 1.0,
    run: function(api, connection, next) {
        api.log("Execute authZeroActions#run", 'debug');
        getSecuredResource(api, connection, next);
        next(connection, true);
    }
};