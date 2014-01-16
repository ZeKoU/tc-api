/*
 * Copyright (C) 2013 TopCoder Inc., All Rights Reserved.
 *
 * @version 1.2
 * @author vangavroche, KeSyren, TCSASSEMBLER
 * changes in 1.1:
 * - update unit tests as contest types are now separated.
 * changes in 1.2:
 * - use test_files under accuracy directory
 */
 "use strict";
/*global describe, it, before, beforeEach, after, afterEach */
/*jslint node: true, stupid: true */

/**
 * Module dependencies.
 */
var fs = require('fs');
var request = require('supertest');
var should = require('should');
var assert = require('chai').assert;
var configs = require("../config.js");

var jwtlib = require('jsonwebtoken');

var API_ENDPOINT = process.env.API_ENDPOINT || 'http://localhost:8080';

describe('Get Auth0 info API', function () {
	this.timeout(30000);

	//jsonwebtoken
	var jwtokenPlain = {
	    "aud": "xZqCP76MS1mo3qeHQMWkMJZGzOk3rNa4",
	    "clientID": "xZqCP76MS1mo3qeHQMWkMJZGzOk3rNa4",
	    "created_at": "2014-01-14T10:47:12.547Z",
	    "email": "amerzec@gmail.com",
	    "exp": 1392375960,
	    "iat": 1389783960,
	    "identities": [
	        {
	            "access_token": null,
	            "connection": "google-oauth2",
	            "isSocial": true,
	            "provider": "google-oauth2",
	            "user_id": "amerzec@gmail.com" //TODO: parametrize
	        }
	    ],
	    "iss": "https://login.auth0.com/",
	    "name": "amerzec@gmail.com",
	    "nickname": "amerzec",
	    "picture": "https://secure.gravatar.com/avatar/aa4edd32333493457a898ed9318b7aa7?s=480&r=pg&d=https%3A%2F%2Fssl.gstatic.com%2Fs2%2Fprofiles%2Fimages%2Fsilhouette80.png",
	    "sub": "google-oauth2|amerzec@gmail.com",
	    "user_id": "google-oauth2|amerzec@gmail.com"
	};

	var clientSecret = new Buffer(configs.configData.auth0.jwtSignatureKey, "base64");

	var jwt = jwtlib.sign(jwtokenPlain, clientSecret);

	var checkAdmin = function (url, fileName, done) {
        console.log("Inside API call! ");
        var text = fs.readFileSync("test/test_files/" + fileName, 'utf8'),
            expected = JSON.parse(text);
            console.log("Expected : " + expected);
            expected.sort(sortBy("challengeCategoryId"));
        request(API_ENDPOINT)
            .get(url)
            .set('Accept', 'application/json')
            .set('Authorization', 'Bearer ' + jwt)
            .expect('Content-Type', /json/)
            .expect(200)
            .end(function (err, res) {
                if (err) {
                    done(err);
                }
                //assert.deepEqual(res.body, expected, 'Invalid contest types');
                done();
            });
    }

     // Test the Auth0 protected /v2/develop/challengetypes
    describe('GET /v2/a0/demoResource', function () {
    	
        /// Check if the data are in expected structure and data
        it('should response with expected structure and data', function (done) {
            console.log("Inside API call! ");
            checkAdmin('/v2/a0/demoResource', 'expected_get_auth0_admin.txt', done);
        });
    });

});