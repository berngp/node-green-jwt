{exec, spawn} = require 'child_process'

handleError = (err) ->
  if err
    console.log "\n\x33[1;36m=>\x33[1;37m Remember that you need: coffee-script@0.9.4 and mocha@0.5.2\x33[0;37m\n"
    console.log err.stack

print = (data) -> console.log data.toString().trim()

task 'install', 'Executes an install of the required packages.', ->
  exec 'npm install'

task 'build', 'Compile Coffeescript source to Javascript', ->
  exec 'mkdir -p lib && coffee -c -o lib src', handleError
  exec 'find lib -name "*.js" -print0 | xargs -0 jslint --stupid'

task 'clean', 'Remove generated Javascripts', ->
  exec 'rm -fr lib', handleError

task 'test', 'Test the app', (options) ->
  console.log "\n\x1B[00;33m=>\x1B[00;32m Running tests..\x1B[00;33m\n"
  mocha = spawn 'mocha', '-c -b --compilers coffee:coffee-script'.split(' ')
  mocha.stdout.on 'data', print
  mocha.stderr.on 'data', print


task 'dev', 'Continuous compilation', ->
  coffee = spawn 'coffee', '-wc --bare -o lib src'.split(' ')
  coffee.stdout.on 'data', print
  coffee.stderr.on 'data', print
