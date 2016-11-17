var ApiBuilder = require('claudia-api-builder'),
  api = new ApiBuilder();

module.exports = api;

var jwt = require('jwt-simple');
var moment = require('moment');

var CognitoHelper = require('./cognito-helper');
var cognito = new CognitoHelper();

var config = require('./server-config');

/*
|--------------------------------------------------------------------------
| Generate JSON Web Token
|--------------------------------------------------------------------------
*/
function createJWT(userId, expiresIn) {
  var exp;
  if(config.EXPIRES_IN) {
    exp = moment().add(config.EXPIRES_IN, 'seconds');
  }
  else if(expiresIn) {
    exp = moment().add(expiresIn, 'seconds');
  }
  else {
    exp = moment().add(14, 'days');
  }

  var payload = {
      sub: userId,
      iat: moment().unix(),
      exp: exp.unix(),
  };

  return jwt.encode(payload, config.TOKEN_SECRET);
};

/*
|--------------------------------------------------------------------------
| Verify JWT token for authenticated requests
|--------------------------------------------------------------------------
*/
function checkJWT(authorization, dontFail) {
  if (!authorization) {
    if(dontFail) {
      return null;
    }
    else {
      return {code: 401, message: 'Missing Authorization header'};
    }
  }
  var token = authorization.split(' ')[1];
  var payload = jwt.decode(token, config.TOKEN_SECRET);
  var now = moment().unix();
  if (payload.exp <= now - 60) {
    if(dontFail) {
      return null;
    }
    else {
      return {code: 401, message: 'Token has expired'};
    }
  }
  return payload.sub;
};

function tokenCallback (err, data) {
  if(err) {
    context.fail(makeError(err));
  }
  else {
    context.succeed({token: createJWT(data.id)});
  }
};

function makeError(err) {
  var errorCode = 'Bad Request';
  switch(err.code) {
    case 404: errorCode = 'Not Found'; break;
    case 409: errorCode = 'Conflict'; break;
    case 401: errorCode = 'Unauthorized'; break;
  }
  return new Error(errorCode + ': ' + (err.error || err));
};

function ensureAuthenticated(request, callback) {
  var t = checkJWT(request.normalizedheaders.token);
  if(t.message) {
    context.fail(new Error('Unauthorized: ' + t.message));
  }
  else {
    callback(t);
  }
};

function dataCallback(err, data) {
  if(err) {
    context.fail(makeError(err));
  }
  else {
    context.succeed(data);
  }
};

/*
|--------------------------------------------------------------------------
| AWS invokes this method to process requests
|--------------------------------------------------------------------------
*/
api.post('/user', function (request) {
  cognito.signup(request.body.name, request.body.email, request.body.password, 
        tokenCallback);
});

api.post('/login', function (request) {
  if (request.body.provider == null) {
  cognito.login(request.body.email, request.body.password, request.body.refreshtoken, 
      tokenCallback);
  } else {
    var provider = operation;
    var userId = checkJWT(request.normalizedheaders.token, true);
    cognito.loginFederated(request.body.provider, 
        request.body.code, request.body.clientId, request.body.redirectUri, userId, 
        tokenCallback);
  }
});

api.get('/me', function (request) {
  ensureAuthenticated(request, function(userId) {
    cognito.getProfile(userId, dataCallback);
  });
});

api.get('/credentials', function (request) {
  ensureAuthenticated(request, function(userId) {
    cognito.getCredentials(userId, dataCallback);
  });
});

api.post('/forgot', function (request) {
  cognito.forgotPassword(request.body.email, dataCallback);
});

api.put('/user', function (request) {
  ensureAuthenticated(request, function(userId) {
    cognito.updatePassword(userId, request.body.password, dataCallback);
  });
});

api.post('/logout', function (request) {
  ensureAuthenticated(request, function(userId) {
    cognito.unlink(userId, request.body.provider, null, dataCallback);
  });
});