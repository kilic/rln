// import key from 'binary-loader!./verifier.key';
// var hexdata = Buffer.from(key, 'ascii').toString('hex');
const js = import('../../pkg/rln.js');
js.then((js) => {
  bufi = Buffer.alloc(64, 1);
  buf0 = Buffer.alloc(32, 0);
  // console.log(buf);
  try {
    let result = js.RLNWasm.generate_proof(bufi, buf0);
    console.log(result);
    console.log(buf0[0]);
  } catch (err) {
    console.log('LOGS ERROR');
    console.log(err);
  }
});
