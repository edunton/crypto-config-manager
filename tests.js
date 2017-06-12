var CConfigM = require('./index');

var test = new CConfigM({path:'./testfiles/secret1.json'})
var ciphertext = test.encrypt({yoojoo:['iuuiouio gt','iiiih'], a:'123'},['$.a']);
var message = test.decrypt(ciphertext);
// var c2 = test.modify(ciphertext,{path:'$.a',value:'1234'})
// var message2 = test.decrypt({payload:c2, withHash:true, withBlocked:true});
// var c3 = test.block(c2,'$.yoojoo')
// var message3 = test.decrypt({payload:c3, withHash:true, withBlocked:true});


console.log(JSON.stringify(ciphertext,null,2));
console.log(JSON.stringify(message,null,2));
// console.log(c2);
// console.log(message2);
// console.log(c3);
// console.log(message3);
