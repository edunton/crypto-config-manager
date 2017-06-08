var CConfigM = require('./cconfigm');

var test = new CConfigM({path:'./package.json', key:'description'})
// Encrypt
var ciphertext = test.encrypt({yoojoo:['iuuiouio gt','iiiih'], a:'123'},['$.a']);
var message = test.decrypt({payload:ciphertext, withHash:true, withBlocked:true});
var c2 = test.modify(ciphertext,{path:'$.a',value:'1234'})
var message2 = test.decrypt({payload:c2, withHash:true, withBlocked:true});
var c3 = test.block(c2,'$.yoojoo')
var message3 = test.decrypt({payload:c3, withHash:true, withBlocked:true});

console.log(ciphertext);
console.log(message);
console.log(c2);
console.log(message2);
console.log(c3);
console.log(message3);
