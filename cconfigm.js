var CryptoJS = require("crypto-js");
var AES = CryptoJS.AES;
var fs = require('fs');
var _ = require('lodash');
var JSONPATH = require('jsonpath');
var SHA256 = require("crypto-js/sha256");

var CConfigM = module.exports = function(options){

  if(!options || typeof options !== 'object')
    throw 'options needs to be defined object'

  var secret = options.secret && typeof options.secret === 'string'?
    options.secret : false;

  if(secret === false){
    if(!options.path || typeof options.path !== 'string')
      throw 'no file path defined';
    var content = fs.readFileSync(options.path);
    var json = JSON.parse(content);
    secret = json[options.key||'secret'];
  }

  if(!secret){
    throw 'secret not defined in secret key file'
  }

  var hardDecrypt = function(payload){
    var dc = AES.decrypt(payload, secret).toString(CryptoJS.enc.Utf8);
    return JSON.parse(dc);
  }

  var self = this;

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

    var config = {config:payload,blocked:blockedPaths}
    return AES.encrypt(JSON.stringify(config), secret).toString();
  }

  self.decrypt = function(input){
    var payload = typeof input === 'string' ? input : input.payload;
    var withBlocked = input.withBlocked;
    var withHash = input.withHash;
    var json = hardDecrypt(payload);

    _.forEach(json.blocked,function(path){
      var value = '_CCMBLOCKED_';
      if(withHash){
        var hashed = SHA256(JSONPATH.value(json.config, path));
        if(hashed !== undefined)
          value += hashed.toString().substring(0,16);
      }
      JSONPATH.value(json.config, path, value);
    })
    return withBlocked ? json : json.config;
  }

  self.modify = function(payload,options){
    var path = options.path;
    var key = options.key;
    var value = options.value;
    if(typeof path !== 'string'){
      throw 'path needs to be a string';
    }
    var json = hardDecrypt(payload);
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
    var json = hardDecrypt(payload);
    paths = typeof paths === 'string' ? [paths] : paths;

    _.forEach(paths,function(x){
      if(typeof x !== 'string')
        throw 'each blocked path needs to be a string';
    });

    json.blocked = _.uniq(json.blocked.concat(paths));

    return self.encrypt(json.config,json.blocked);
  }
}
