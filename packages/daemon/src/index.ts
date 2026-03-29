import { createSafeBrowseServer, startSafeBrowseDaemon } from "./server.js";

export { createSafeBrowseServer, startSafeBrowseDaemon } from "./server.js";

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/"))) {
  startSafeBrowseDaemon().then((server) => {
    const address = server.address();
    console.log(JSON.stringify({ status: "listening", address }, null, 2));
  });
}
