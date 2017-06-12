var CryptoJS = require("crypto-js");
var AES = CryptoJS.AES;
var fs = require('fs');
var _ = require('lodash');
var JSONPATH = require('jsonpath');
var SHA256 = require("crypto-js/sha256");

const INTEGLEN = 10;

var Core = module.exports = function(options){

  /******************************
   * initialize
   ******************************/
  if(!options || typeof options !== 'object')
    throw 'options needs to be defined object'

  var _secret = options.secret && typeof options.secret === 'string'?
    options.secret : false;

  var _chunkSize = options.chunkSize > 0 ? options.chunkSize : 60;

  if(_secret === false){
    if(!options.path || typeof options.path !== 'string')
      throw 'no file path defined';
    var content = fs.readFileSync(options.path);
    var json = JSON.parse(content);
    _secret = JSONPATH.value(json, options.key||'$.secret');//json[options.keypath||'secret'];
  }

  if(!_secret){
    throw 'secret not defined in secret key file'
  }

  var self = this;

  /******************************
   * public methods
   ******************************/

  self.encrypt = function(payload, blockedPaths){
    payload = typeof payload === 'object' ? payload : JSON.parse(payload);
    blockedPaths = blockedPaths || [];
    blockedPaths = _.uniq(blockedPaths);
    if(!_.isArray(blockedPaths))
    {
      throw 'blocked paths need to be an array';
    }

    _.forEach(blockedPaths,function(x){
      if(typeof x !== 'string')
        throw 'each blocked path needs to be a string';
    })

    var timestamp = dateSeconds();
    var timestr = secondsToString(timestamp);
    var json = {
      config:payload,
      blocked:blockedPaths,
      changes: 0,
      created:timestamp,
      updated:timestamp
    }
    var ccmjson = aesEncrypt(json,40);
    var token = makeIntegrityToken(json);

    return {
      ccmjson : ccmjson,
      integrity : {
        token : token,
        changes: 0,
        created:timestr,
        updated:timestr
      }
    };
  }

  self.hardDecrypt = function(input){

    var issue = inputIssue(input);
    if(issue)
      throw issue;
    var ccmjson = _.join(input.ccmjson,'');
    var json = hardDecryptAux(ccmjson);
    var passed = checkIntegrity(json,input.integrity);

    if(!passed)
    {
      throw 'input failed integrity check';
    }

    return json;
  }

  self.softDecrypt = function(input){
    var json = self.hardDecrypt(input);

    _.forEach(json.blocked,function(path){
      var value = '::CCMBLOCKED::'
        + (typeof JSONPATH.value(json.config, path)).toUpperCase()
        + '::';
      JSONPATH.value(json.config, path, value);
    })
    return json;
  }

  self.decrypt = self.softDecrypt; //alias

  self.modify = function(payload,options){
    var path = options.path;
    var key = options.key;
    var value = options.value;

    var json = self.hardDecrypt(payload);
    if(key !== undefined){
      var obj = JSONPATH.value(json.config, path);
      obj[key] = value;
    }
    else {
      JSONPATH.value(json.config, path, value);
    }

    return self.encrypt(json.config,json.blocked);
  }

  self.block = function(payload,paths){
    var json = self.hardDecrypt(payload);
    paths = typeof paths === 'string' ? [paths] : paths;

    _.forEach(paths,function(x){
      if(typeof x !== 'string')
        throw 'each blocked path needs to be a string';
    });

    json.blocked = _.uniq(json.blocked.concat(paths));

    return self.encrypt(json.config,json.blocked);
  }

  /******************************
   * private methods
   ******************************/

  var shaHash = function(input){
    return SHA256(input).toString();
  }

  var aesEncrypt = function(payload){
    var str = AES.encrypt(JSON.stringify(payload), _secret).toString();
    return _.map(
      _.chunk(str.split(''), _chunkSize),
      function(chunk){return _.join(chunk,'')}
    )
  }

  var makeIntegrityToken = function(json){
    var hash = shaHash(json).substring(0,INTEGLEN);
    return AES.encrypt(hash, _secret).toString();
  }

  var checkIntegrity = function(json, integrity){
    var hash = shaHash(json).substring(0,INTEGLEN);
    var decryptToken = AES.decrypt(integrity.token, _secret).toString(CryptoJS.enc.Utf8);
    return hash === decryptToken
        && integrity.changes === json.changes
        && json.created === dateSeconds(integrity.created)
        && json.updated === dateSeconds(integrity.created)
  }

  var hardDecryptAux = function(payload){
    var dc = AES.decrypt(payload, _secret).toString(CryptoJS.enc.Utf8);
    return JSON.parse(dc);
  }

  var inputIssue =  function(input){
    var issue = false;
    if(!_.isArray(input.ccmjson))
    {
      issue = 'ccmjson array not provided';
    }

    if(_.isUndefined(input.integrity)
     ||_.isUndefined(input.integrity.token)
     ||_.isUndefined(input.integrity.changes)
     ||_.isUndefined(input.integrity.created)
     ||_.isUndefined(input.integrity.updated)){
       issue = 'integrity object is invalid';
     }

    _.forEach(input.ccmjson,function(x){
      if(typeof x !== 'string')
        issue = 'ccmjson array not string array';
    });

    return issue;
  }

  var dateSeconds = function(datestring)
  {
    if(datestring === undefined){
      return Math.floor((new Date()).valueOf() / 1000);
    }
    return Math.floor(Date.parse(datestring).valueOf() / 1000);
  }

  var secondsToString = function(seconds) {
    return new Date(seconds * 1000).toUTCString();
  }
}
