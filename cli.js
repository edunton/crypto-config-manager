#!/usr/bin/env node

/**
 * Module dependencies.
 */

var program = require('commander');

program
  .version('0.0.1');
program
  .command('server <secret_file>')
  .description('run a server to encrypt and decrypt configuration files')
  .option('-k, --key <key>', 'key in secret key file where its value is the secret')
  .action(function(file, options){
    var mode = options.setup_mode || "normal";
    env = env || 'all';
    console.log('setup for %s env(s) with %s mode', env, mode);
  });
program
  .command('client <url>')
  .description('run a client to encrypt and decrypt configuration files on a remote server')
  .option('-e, --encrypt <path>', 'path to file with content to encrypt')
  .option('-d, --decrypt <path>', 'decrypt file in the path')
  .option('-m, --modify <path> <jsonpath>', 'decrypt file in the path')
  .action(function(url, options){
    var mode = options.setup_mode || "normal";
    url = url || 'all';
    console.log('setup for %s env(s) with %s mode', url);
    console.log();
  });
program
  .command('local <secret_file>')
  .description('run against a local secret file')
  .action(function(env, options){
    console.log('deploying "%s"', env);
  });
program.parse(process.argv);

    // .option('-s, --server', 'use as server')
    // .option('-c, --client', 'use as client')
    // .option('-l, --location', 'connects to remote cconfigm server')
    // .option('-f, --file <path>', 'path to secret key file')
    // .option('-k, --key <key>', 'key in secret key file where its value is the secret')
