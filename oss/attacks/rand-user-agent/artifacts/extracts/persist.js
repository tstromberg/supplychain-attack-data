const Y = path.join(
  process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local"),
  "Programs\\Python\\Python3127",
);
env.PATH = Y + ";" + process.env.PATH;
