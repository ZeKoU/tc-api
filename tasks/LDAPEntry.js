/*
 * Copyright (C) 2013 TopCoder Inc., All Rights Reserved.
 *
 * Version: 1.0
 * Author: TCSASSEMBLER
 */
"use strict";

/**
 * Dependency 
 */
var ldap = require('ldapjs'), async = require('async'), Ber = require('asn1').Ber;

/// environment variables
var ldap_host = process.env.TC_LDAP_HOST,
    ldap_host_port = process.env.TC_LDAP_PORT,
    ldap_password = process.env.TC_LDAP_PASSWORD,
    ldap_host_bind_dn = process.env.TC_BIND_DN,
    topcoder_member_base_dn = process.env.TC_LDAP_MEMBER_BASE_DN,
    topcoder_member_active = 'A',
    topcoder_member_unactive = 'U';

/** The OID of the modify password extended operation */
var LDAP_EXOP_X_MODIFY_PASSWD = '1.3.6.1.4.1.4203.1.11.1';
/** The BER tag for the modify password dn entry */
var LDAP_TAG_EXOP_X_MODIFY_PASSWD_ID = 0x80;
/** The BER tag for the modify password new password entry */
var LDAP_TAG_EXOP_X_MODIFY_PASSWD_OLD = 0x81;
/** The BER tag for the modify password new password entry */
var LDAP_TAG_EXOP_X_MODIFY_PASSWD_NEW = 0x82;

/**
 * This function is used to translate the error of LADP
 * into a form of normal object
 * 
 * @param {Object} err - the error object returned by ldapjs
 * @param {Object} normal object of error
 */
var translateLdapError = function (err) {
    if (err) {
        return {
            dn: err.dn,
            code: err.code,
            name: err.name,
            message: err.message
        };
    }
    return {};
};

/**
 * This function is used to check the existence of 
 * given paramters and ensure it not be empty
 * 
 * @param {Object} params - a object of paramters
 * @param {String} name - the name of the to-be-checked parameter
 * @param {Boolean} true if params contains the given paramter 
 *                      and it is not empty; false otherwise. 
 */
var checkParameter = function (params, name) {
    return params.hasOwnProperty(name) && (params[name].toString().trim().length >= 1);
};

/**
 * Function used to create a client
 */
var createClient = function () {
    return ldap.createClient({
        url: 'ldaps://' + ldap_host + ':' + ldap_host_port,
        tlsOptions: {
            rejectUnauthorized: false
        }
    });
};

/**
 * Function used to bind a ldap server
 * 
 * @param {Object} api - object used to access infrustrature
 * @param {Object} client - an object of current client of ldap server
 * @param {Function} callback - a async callback funtion with prototype like callback(err, results)
 */
var bindClient = function (api, client, callback) {
    client.bind(ldap_host_bind_dn, ldap_password, function (err) {
        if (err) {
            api.log('binding failed');
            callback('cannot bind to ldap server', translateLdapError(err));
        } else {
            api.log('Sucessfully bind to ldap server', 'info');
            callback(null, 'bind to ldap server');
        }
    });
};

/**
 * Function used to add an entry in ldap server
 * 
 * @param {Object} api - object used to access infrustrature
 * @param {Object} client - an object of current client of ldap server
 * @param {Object} params - the parameters of task
 * @param {Function} callback - a async callback funtion with prototype like callback(err, results)
 */
var addClient = function (api, client, params, callback) {
    var dn = 'uid=' + params.userId + ', ' + topcoder_member_base_dn,
        entry = {
            uid: params.userId,
            handle: params.handle,
            objectClass: ['tc-member', 'top'],
            status: topcoder_member_unactive,
            userPassword: params.password
        };
    client.add(dn, entry, function (err) {
        if (err) {
            client.unbind();
            callback('cannot add to ldap server', translateLdapError(err));
        } else {
            api.log('Sucessfully add to ldap server', 'info');
            callback(null, 'add to ldap server');
        }
    });
};

/**
 * Function used to update the password in order to create a hashed version of it
 * 
 * @param {Object} api - object used to access infrustrature
 * @param {Object} client - an object of current client of ldap server
 * @param {Object} params - the parameters of task
 * @param {Function} callback - a async callback funtion with prototype like callback(err, results)
 */
var passwordModify = function (api, client, params, callback) {
    var dn = 'uid=' + params.userId + ', ' + topcoder_member_base_dn;
    var op = params.oldPassword || params.password;
    var np = params.newPassword || params.password;
    var writer = new Ber.Writer();
    writer.startSequence();
    writer.writeString(dn, LDAP_TAG_EXOP_X_MODIFY_PASSWD_ID);
    writer.writeString(op, LDAP_TAG_EXOP_X_MODIFY_PASSWD_OLD);
    writer.writeString(np, LDAP_TAG_EXOP_X_MODIFY_PASSWD_NEW);
    writer.endSequence();

    client.exop(LDAP_EXOP_X_MODIFY_PASSWD, writer.buffer, function(err, result) {
        if (err) {
            client.unbind();
            callback('cannot modify password for user', translateLdapError(err));
        } else {
            api.log('Sucessfully modified password', 'info');
            callback(null, 'modified password');
        }
    });
};

/**
 * Function used to modify an entry in ldap server
 * 
 * @param {Object} api - object used to access infrustrature
 * @param {Object} client - an object of current client of ldap server
 * @param {Object} params - the parameters of task
 * @param {Function} callback - a async callback funtion with prototype like callback(err, results)
 */
var modifyClient = function (api, client, params, callback) {
    var dn = 'uid=' + params.userId + ', ' + topcoder_member_base_dn,
        change = new ldap.Change({
            operation: 'replace',
            modification: {
                status: [topcoder_member_active]
            }
        });
    client.modify(dn, change, function (err) {
        if (err) {
            client.unbind();
            callback('cannot modify to ldap server', translateLdapError(err));
        } else {
            api.log('Sucessfully modify to ldap server', 'info');
            callback(null, 'modify to ldap server');
        }
    });
};

/**
 * Task - used to add a ldap entry 
 */
exports.addMemberProfileLDAPEntry = {
    name: 'addMemberProfileLDAPEntry',
    description: 'I will add an ldap entry to ldap server',
    scope: 'any',
    frequency: 0,
    /**
     * Main function of addMemberProfileLDAPEntry tasks
     *
     * @param {Object} api - object used to access infrustrature
     * @param {Object} params require fields: userId, handle, password
     * @param {Function} next - callback function
     */
    run: function (api, params, next) {
        api.log('Enter addMemberProfileLDAPEntry task#run', 'debug');

        var client, error, index, requiredParams = ['userId', 'handle', 'password'];

        for (index = 0; index < requiredParams.length; index += 1) {
            error = api.helper.checkDefined(params[requiredParams[index]], requiredParams[index]);
            if (error) {
                api.log("task addMemberProfileLDAPEntry: error occured: " + error + " " + (error.stack || ''), "error");
                return next(null, true);
            }
        }
try {
        async.series([
            function (callback) {
                client  = createClient();
                callback(null, 'create client');
            },
            function (callback) {
                bindClient(api, client, callback);
            },
            function (callback) {
                addClient(api, client, params, callback);
            },
            function (callback) {
                passwordModify(api, client, params, callback);
            }
        ], function (err, result) {
            if (err) {
                error = result.pop();
                api.log('task addMemberProfileLDAPEntry: error occurred: ' + err + " " + (err.stack || ''), "error");
            } else {
                client.unbind();
            }
            api.log('Leave addMemberProfileLDAPEntry task', 'debug');
        });
} catch (error) {
  console.log('CAUGHT: ' + error);
}
        return next(null, true);
    }
};

/**
 * Task - used to activate a ldap entry 
 */
exports.activateMemberProfileLDAPEntry = {
    name: 'activateMemberProfileLDAPEntry',
    description: 'I will activate an ldap entry to ldap server',
    scope: 'any',
    frequency: 0,

    /**
     * Main function of activateMemberProfileLDAPEntry tasks
     *
     * @param {Object} api - object used to access infrustrature
     * @param {Object} params require fields: userId
     * @param {Function} next - callback function
     */
    run: function (api, params, next) {
        api.log('Enter activateMemberProfileLDAPEntry task#run', 'debug');
        
        var client, error;

        // pararms validation

        error = api.helper.checkDefined(params['userId'], 'userId');
        if (error) {
            api.log("task activateMemberProfileLDAPEntry: error occured: " + error + " " + (error.stack || ''), "error");
            return next(null, true);
        }

        async.series([
            function (callback) {
                client = createClient();
                
                callback(null, 'create client');
            },
            function (callback) {
                bindClient(api, client, callback);
            },
            function (callback) {
                modifyClient(api, client, params, callback);
            }
        ], function (err, result) {
            if (err) {
                error = result.pop();
                api.log('task activateMemberProfileLDAPEntry ' + err + ' ', 'error', error);
            } else {
                client.unbind();
            }
            api.log('Leave activateMemberProfileLDAPEntry task', 'debug');
        });
        return next(null, true);
    }
};

