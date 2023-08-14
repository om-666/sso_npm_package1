const _ = require('lodash');
const jwt = require('jsonwebtoken');
const envHelper = require('../helpers/environmentVariablesHelper');
const { encrypt, decrypt } = require('../helpers/crypto');
const {encrypt, decrypt} = require('../helpers/crypto');
const {
  verifySignature, verifyIdentifier, verifyToken, fetchUserWithExternalId, createUser, fetchUserDetails,
  createSession, updateContact, updateRoles, sendSsoKafkaMessage, migrateUser, freeUpUser, getIdentifier,
  orgSearch
} = require('./../helpers/ssoHelper');
const telemetryHelper = require('../helpers/telemetryHelper');
const {generateAuthToken, getGrantFromCode} = require('../helpers/keyCloakHelperService');
const {parseJson, isDateExpired} = require('../helpers/utilityService');
const {getUserIdFromToken} = require('../helpers/jwtHelper');
const fs = require('fs');
const externalKey = envHelper.CRYPTO_ENCRYPTION_KEY_EXTERNAL;
const successUrl = '/sso/sign-in/success';
const updateContactUrl = '/sign-in/sso/update/contact';
const errorUrl = '/sso/sign-in/error';
const { logger } = require('@project-sunbird/logger');
const url = require('url');
const {acceptTncAndGenerateToken} = require('../helpers/userService');
const VDNURL = envHelper.vdnURL || 'https://dockstaging.sunbirded.org';
const { getAuthToken } = require('../helpers/kongTokenHelper');
 

const express = require('express');
const app = express();

function initializeRoute() {
    app.get('/v2/user/session/create', async (req, res) => {
        app.get('/v2/user/session/create', async (req, res) => { // <--- Remove this duplicate line
            logger.info({msg: '/v2/user/session/create called'});
            let jwtPayload, userDetails, redirectUrl, errType, orgDetails;
            try {
                errType = 'VERIFY_SIGNATURE';
                await verifySignature(req.query.token); // it is coming from the ssohelper.js file
                jwtPayload = jwt.decode(req.query.token);
                if (!jwtPayload.state_id || !jwtPayload.school_id || !jwtPayload.name || !jwtPayload.sub) {
                  errType = 'PAYLOAD_DATA_MISSING';
                  throw 'some of the JWT payload is missing';
                }
                req.session.jwtPayload = jwtPayload;
                req.session.migrateAccountInfo = {
                  stateToken: req.query.token
                };
                errType = 'VERIFY_TOKEN';
                verifyToken(jwtPayload); // it is comes from the ssohelper.js file
                errType = 'USER_FETCH_API';
                userDetails = await fetchUserWithExternalId(jwtPayload, req);// it is comes from the ssohelper.js file
                if (_.get(req,'cookies.redirectPath')){
                  res.cookie ('userDetails', JSON.stringify(encrypt(userDetails.userName, externalKey)));
                }
                req.session.userDetails = userDetails;
                logger.info({msg: "userDetails fetched" + userDetails});
                if(!_.isEmpty(userDetails) && (userDetails.phone || userDetails.email)) {
                  redirectUrl = successUrl + getEncyptedQueryParams({userName: userDetails.userName});
                  logger.info({
                    msg: 'sso session create v2 api, successfully redirected to success page',
                    additionalInfo: {
                      state_id: jwtPayload.state_id,
                      jwtPayload: jwtPayload,
                      query: req.query,
                      userDetails: userDetails,
                      redirectUrl: redirectUrl
                    }
                  })
                } else {
                  errType = 'ORG_SEARCH';
                  orgDetails = await orgSearch(jwtPayload.school_id, req);
                  if (!(_.get(orgDetails, 'result.response.count') > 0)) {
                    throw 'SCHOOL_ID_NOT_REGISTERED'
                  }
                  const dataToEncrypt = {
                    identifier: (userDetails && userDetails.id) ? userDetails.id : ''
                  };
                  errType = 'ERROR_ENCRYPTING_DATA_SESSION_CREATE';
                  req.session.userEncryptedInfo = encrypt(JSON.stringify(dataToEncrypt));
                  redirectUrl = updateContactUrl; // verify phone then create user
                  logger.info({
                    msg:'sso session create v2 api, successfully redirected to update phone page',
                    additionalInfo: {
                      state_id: jwtPayload.state_id,
                      jwtPayload: jwtPayload,
                      query: req.query,
                      userDetails: userDetails,
                      redirectUrl: redirectUrl
                    }
                  })
                }
              }catch (error) {
                redirectUrl = `${errorUrl}?error_message=` + getErrorMessage(error, errType);
                logger.error({
                  msg: 'sso session create v2 api failed',
                  error,
                  additionalInfo: {
                    errorType: errType,
                    jwtPayload: jwtPayload,
                    query: req.query,
                    userDetails: userDetails,
                    redirectUrl: redirectUrl
                  }
                })
                logErrorEvent(req, errType, error);
              } finally {
                res.redirect(redirectUrl || errorUrl);
              }
        });
    });
}

// Export the initializeRoute function
module.exports = {
    initializeRoute,
};
